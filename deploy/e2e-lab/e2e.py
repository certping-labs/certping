#!/usr/bin/env python3
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

"""CertPing end-to-end check against the local lab (docker-compose.yml in this folder).

Drives the same API the web app uses, and checks every result where it really lands:
sign-in, password change, DNS and Kubernetes credentials, issuance through a real ACME DNS-01
challenge, deployment into Kubernetes, discovery of that certificate, renewal and redeployment,
and email. Exits non-zero on the first failure. Run it through run.sh.
"""
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("CERTPING_E2E_URL", "http://localhost:8090")
MAILPIT = os.environ.get("CERTPING_E2E_MAILPIT", "http://localhost:8025")
HERE = os.path.dirname(os.path.abspath(__file__))
DOMAIN = "app.lab.test"
NAMESPACE = "lab"
SECRET_NAME = "app-lab-test-tls"
results = []


def compose(*args, check=True):
    out = subprocess.run(["docker", "compose", *args], cwd=HERE, capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def kubectl(*args, stdin=None):
    out = subprocess.run(["docker", "compose", "exec", "-T", "k3s", "kubectl", *args],
                         cwd=HERE, capture_output=True, text=True, input=stdin)
    if out.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def http(method, path, token=None, body=None, base=BASE, ok=(200, 201, 202, 204)):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    payload = json.loads(raw) if raw else None
    if status not in ok:
        raise RuntimeError(f"{method} {path} -> {status}: {raw[:500].decode(errors='replace')}")
    return payload


def step(name):
    def wrap(fn):
        def run(*a, **kw):
            started = time.time()
            print(f"... {name}", flush=True)
            try:
                value = fn(*a, **kw)
            except Exception as e:
                results.append((name, False, str(e)))
                print(f"FAIL {name}: {e}", flush=True)
                summary()
                sys.exit(1)
            results.append((name, True, f"{time.time() - started:.0f}s"))
            print(f"PASS {name} ({time.time() - started:.0f}s)", flush=True)
            return value
        return run
    return wrap


def wait_for(what, fn, timeout=300, interval=5):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise RuntimeError(f"timed out after {timeout}s waiting for {what}")


def serial_of_pem(pem):
    out = subprocess.run(["openssl", "x509", "-noout", "-serial"], input=pem,
                         capture_output=True, text=True, check=True).stdout
    return out.strip().split("=", 1)[1].upper().lstrip("0")


def norm_serial(value):
    return re.sub(r"[^0-9A-F]", "", (value or "").upper()).lstrip("0")


@step("First admin signs in with the generated password and must change it")
def sign_in():
    # The log never shows the password; certping-admin reads it from the volume's config.env.
    details = compose("exec", "-T", "certping", "certping-admin")
    match = re.search(r"Password:\s+(\S+)", details)
    if not match:
        raise RuntimeError("no generated password from certping-admin")
    old = match.group(1)
    login = http("POST", "/api/auth/login", body={"identifier": "admin", "password": old}, ok=(200, 401))
    if login is None or "token" not in login:
        # Already changed by an earlier run of this script on the same volume.
        new = open(os.path.join(HERE, ".work", "admin-password")).read().strip()
        return http("POST", "/api/auth/login", body={"identifier": "admin", "password": new})["token"]
    if not login.get("mustChangePassword"):
        raise RuntimeError("mustChangePassword should be true for the generated password")
    new = "Lab-" + secrets.token_urlsafe(18) + "9a!"
    http("POST", "/api/auth/change-password", login["token"],
         {"currentPassword": old, "newPassword": new, "confirmPassword": new})
    with open(os.path.join(HERE, ".work", "admin-password"), "w") as f:
        f.write(new)
    again = http("POST", "/api/auth/login", body={"identifier": "admin", "password": new})
    if again.get("mustChangePassword"):
        raise RuntimeError("mustChangePassword still true after the change")
    return again["token"]


@step("DNS credential (CertPing DNS API) is accepted")
def dns_credential(token):
    key = "cpk_live_lab12345" + secrets.token_hex(12)
    cred = http("POST", "/api/v1/credentials/dns", token, {
        "provider": "CERTPING",
        "description": "Lab DNS",
        "credJson": {"apiKey": key},
        "configJson": {"tokenId": 1, "tokenPrefix": "cpk_live_lab12345",
                       "expiresAt": "2030-01-01T00:00:00Z"},
    })
    return cred["credentialXref"]


@step("Kubernetes deployment credential (service account token) is accepted")
def k8s_credential(token):
    wait_for("k3s API", lambda: "Ready" in kubectl("get", "nodes"), timeout=120)
    manifest = f"""
apiVersion: v1
kind: Namespace
metadata: {{name: {NAMESPACE}}}
---
apiVersion: v1
kind: ServiceAccount
metadata: {{name: certping, namespace: {NAMESPACE}}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {{name: certping-secrets, namespace: {NAMESPACE}}}
rules:
- apiGroups: [""]
  resources: [secrets]
  verbs: [get, list, watch, create, update, patch, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {{name: certping-secrets, namespace: {NAMESPACE}}}
roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: Role, name: certping-secrets}}
subjects: [{{kind: ServiceAccount, name: certping, namespace: {NAMESPACE}}}]
"""
    kubectl("apply", "-f", "-", stdin=manifest)
    sa_token = kubectl("-n", NAMESPACE, "create", "token", "certping", "--duration=24h").strip()
    ca = compose("exec", "-T", "k3s", "cat", "/var/lib/rancher/k3s/server/tls/server-ca.crt")
    cred = http("POST", "/api/v1/credentials/deployment", token, {
        "provider": "KUBERNETES_SECRETS",
        "description": "Lab cluster",
        "configJson": {"authMethod": "SA_TOKEN", "clusterName": "lab", "namespaces": [NAMESPACE]},
        "credJson": {"apiServer": "https://k3s:6443", "bearerToken": sa_token, "caCertPem": ca},
    })
    return cred["credentialXref"]


def get_cert(token, xref):
    return http("GET", f"/api/v1/certs/{xref}", token)


def cert_status(cert):
    return (cert.get("status") or cert.get("certStatus") or "").upper()


def secret_serial():
    raw = kubectl("-n", NAMESPACE, "get", "secret", SECRET_NAME, "-o", "jsonpath={.data.tls\\.crt}")
    return serial_of_pem(base64.b64decode(raw).decode()) if raw else None


@step("Certificate is issued through a real ACME DNS-01 challenge and deployed to Kubernetes")
def issue(token, dns_xref, k8s_xref):
    resp = http("POST", "/api/v1/certs/issue", token, {
        "domain": DOMAIN, "wildcard": False, "san": False, "caProvider": "LETS_ENCRYPT",
        "dnsCredentialXref": dns_xref,
        "deploymentTargets": [k8s_xref],
        "deploymentTargetConfigs": [{
            "deploymentCredentialXref": k8s_xref,
            "config": {"nsSecretMap": [{NAMESPACE: SECRET_NAME}]},
        }],
    })
    xref = resp.get("certXref") or resp.get("certificateXref") or (resp.get("certificate") or {}).get("certXref")
    if not xref:
        raise RuntimeError(f"no certXref in issue response: {resp}")

    def issued():
        cert = get_cert(token, xref)
        status = cert_status(cert)
        if status in ("FAILED", "ERROR"):
            raise RuntimeError(f"issuance failed: {json.dumps(cert)[:600]}")
        return cert if status in ("ACTIVE", "ISSUED") else None

    cert = wait_for("issuance", issued, timeout=420)
    deployed = wait_for("the Kubernetes secret", lambda: secret_serial(), timeout=300)
    api_serial = norm_serial(cert.get("serialNumber") or cert.get("serial"))
    if api_serial and api_serial != deployed:
        raise RuntimeError(f"secret serial {deployed} differs from the issued serial {api_serial}")
    return xref, deployed


SECRET_FIELD = re.compile(r"(secret|password|private.?key|api.?key|key.?value|pem|credjson)", re.I)


def secret_fields(node, path=""):
    """Every field name in the response that could carry key material ("keyType" is allowed)."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if SECRET_FIELD.search(key):
                found.append(f"{path}.{key}")
            found += secret_fields(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            found += secret_fields(value, f"{path}[{i}]")
    return found


@step("Certificate authorities show the agent's ACME account (Pebble, CUSTOM) and no key material")
def certificate_authorities(token):
    def account_reported():
        resp = http("GET", "/api/v1/certificate-authorities", token)
        le = next((a for a in resp.get("authorities", []) if a.get("id") == "LETS_ENCRYPT"), None)
        if not le or le.get("status") != "CONFIGURED":
            return None
        for agent in le.get("agents") or []:
            acme = agent.get("acme") or {}
            if acme.get("environment") == "CUSTOM" and acme.get("accountUrl"):
                return resp
        return None

    # The agent reports a new account with its next heartbeat tick, a few seconds after issuance.
    resp = wait_for("the ACME account in the certificate authorities", account_reported, timeout=120)
    body = json.dumps(resp)
    for marker in ("-----BEGIN", "PRIVATE KEY"):
        if marker in body:
            raise RuntimeError(f"certificate authorities response contains {marker!r}")
    leaked = secret_fields(resp)
    if leaked:
        raise RuntimeError(f"certificate authorities response has secret-like fields: {leaked}")
    ids = [a.get("id") for a in resp["authorities"]]
    if ids != ["LETS_ENCRYPT", "DIGICERT", "GLOBALSIGN"]:
        raise RuntimeError(f"unexpected authorities: {ids}")


@step("Agents page shows the bundled agent online with what it reports, and no secrets")
def agents_page(token):
    def bundled_online():
        resp = http("GET", "/api/v1/agents", token)
        for agent in resp.get("agents") or []:
            if agent.get("bundled") is True and agent.get("status") == "ONLINE" and agent.get("version"):
                return resp, agent
        return None

    # The agent sends its info with the next heartbeat after it starts.
    resp, agent = wait_for("the bundled agent online on the Agents page", bundled_online, timeout=180)
    problems = []
    if agent.get("secretStore") != "LOCAL":
        problems.append(f"secretStore={agent.get('secretStore')!r}")
    if agent.get("maxConcurrentJobs") != 8:
        problems.append(f"maxConcurrentJobs={agent.get('maxConcurrentJobs')!r}")
    caps = agent.get("capabilities") or {}
    for kind in ("deploymentTargets", "discoveryTargets", "dnsProviders"):
        if not caps.get(kind):
            problems.append(f"no {kind}")
    if problems:
        raise RuntimeError(f"bundled agent reports {problems}: {agent}")
    body = json.dumps(resp)
    for marker in ("-----BEGIN", "PRIVATE KEY"):
        if marker in body:
            raise RuntimeError(f"agents response contains {marker!r}")
    # Only the token prefix (cpa_ and six characters) may appear, never a whole token.
    if re.search(r"cpa_[A-Za-z0-9_-]{7,}", body):
        raise RuntimeError("agents response contains an agent token")
    # secretStore names the provider (LOCAL), not a secret.
    leaked = [f for f in secret_fields(resp) if not f.endswith(".secretStore")]
    if leaked:
        raise RuntimeError(f"agents response has secret-like fields: {leaked}")
    return agent


@step("Kubernetes discovery finds the deployed certificate and marks it managed")
def discover(token, k8s_xref, serial):
    http("POST", "/api/v1/discovery/trigger", token,
         {"targetType": "KUBERNETES_SECRETS", "credentialXref": k8s_xref})

    def found():
        page = http("GET", "/api/v1/discovery/certs?size=100", token)
        items = page.get("content") or page.get("items") or []
        for item in items:
            if norm_serial(item.get("serialNumber")) == serial:
                return item
        return None

    item = wait_for("the discovered certificate", found, timeout=300)
    if item.get("managed") is not True:
        raise RuntimeError(f"discovered certificate is not marked managed: {item}")

    def scans_finished():
        configs = http("GET", "/api/v1/discovery/trigger", token) or []
        configs = configs if isinstance(configs, list) else configs.get("items", [])
        running = [c for c in configs if (c.get("status") or "").upper() in ("STARTED", "IN_PROGRESS")]
        return not running

    wait_for("the scan status to show complete (not stuck as running)", scans_finished, timeout=120)


@step("Renewal issues a new certificate and redeploys it to Kubernetes")
def renew(token, xref, old_serial):
    http("POST", f"/api/v1/certs/{xref}/renew", token, {})
    new = wait_for("the renewed certificate in Kubernetes",
                   lambda: (s := secret_serial()) != old_serial and s, timeout=420)
    return new


def psql(sql):
    return compose("exec", "-T", "certping", "su", "postgres", "-c",
                   f"psql -d certping -v ON_ERROR_STOP=1 -tAc \"{sql}\"").strip()


@step("Expiry alert email is sent for a certificate inside the 14-day window")
def expiry_alert():
    # Pebble certificates last ten days, so the 14-day alert is due at the next job run (every minute here).
    def alert():
        page = http("GET", "/api/v1/messages", base=MAILPIT)
        subjects = [m.get("Subject", "") for m in page.get("messages", [])]
        return [s for s in subjects if "expir" in s.lower()] or None

    return wait_for("an expiry alert email", alert, timeout=240)


@step("Scheduler renews a due certificate on its own and redeploys it")
def auto_renew(xref, old_serial):
    # Move the renewal date to now, as if the certificate had aged; the renewal job runs every minute.
    # Renewal moves the schedule to the new certificate record, so target the live schedule row.
    changed = psql("UPDATE renewal_schedule SET renewal_eligible_at = now() - interval '1 minute' "
                   "WHERE enabled AND NOT is_deleted RETURNING certificate_xref")
    if not changed:
        raise RuntimeError("no active renewal schedule to move")
    return wait_for("the scheduler's renewal in Kubernetes",
                    lambda: (s := secret_serial()) != old_serial and s, timeout=300)


@step("Locked-out admin recovers with certping-admin reset-password (no email needed)")
def admin_reset():
    out = compose("exec", "-T", "certping", "certping-admin", "reset-password", "admin")
    match = re.search(r"token=(\S+)", out)
    if not match:
        raise RuntimeError(f"no reset link in: {out}")
    new = "Reset-" + secrets.token_urlsafe(18) + "7b!"
    http("PUT", f"/api/auth/reset-password/{match.group(1)}", body={"newPassword": new, "confirmPassword": new})
    token = http("POST", "/api/auth/login", body={"identifier": "admin", "password": new})["token"]
    with open(os.path.join(HERE, ".work", "admin-password"), "w") as f:
        f.write(new)
    return token


@step("Reset links never reach the notification list or the stored records")
def reset_links_hidden(token):
    email_address = psql("SELECT email FROM users WHERE lower(username) = 'admin' AND NOT is_deleted LIMIT 1")
    if not email_address:
        raise RuntimeError("no email for the admin user")
    http("POST", "/api/auth/forgot-password", body={"email": email_address})

    def reset_mail():
        page = http("GET", "/api/v1/messages", base=MAILPIT)
        return [m for m in page.get("messages", []) if "reset" in (m.get("Subject") or "").lower()] or None

    wait_for("the forgot-password email", reset_mail, timeout=180)

    def reset_record():
        page = http("GET", "/api/notifications?size=100", token)
        rows = (page or {}).get("data") or []
        return page if any((r.get("templateName") or "") == "reset-password" for r in rows) else None

    page = wait_for("the reset-password record in the notification list", reset_record, timeout=120)
    listed = json.dumps(page)
    leaks = [marker for marker in ("token=", "payloadJson", "reset-password?", "eyJ") if marker in listed]
    if leaks:
        raise RuntimeError(f"notification list exposes {leaks}: {listed[:600]}")
    stored = psql("SELECT count(*) FROM notification_records WHERE payload_json ~ 'token=' "
                  "OR payload_json ~ '\\\"resetLink\\\":\\\"http'")
    if stored != "0":
        raise RuntimeError(f"{stored} notification records still store a reset link or token")


@step("Value summary counts the work CertPing did (hours saved, renewals, deployments)")
def value_summary(token):
    v = http("GET", "/api/v1/certs/value-summary", token)
    expected = {"issuances": 1, "renewals": 2, "scheduledRenewals": 1, "automatedDeployments": 3}
    wrong = {k: v.get(k) for k, n in expected.items() if (v.get(k) or 0) < n}
    if wrong or v.get("minutesSaved", 0) <= 0:
        raise RuntimeError(f"value summary is short: {v}")
    return v


@step("Email reaches the mailbox")
def email():
    def any_mail():
        page = http("GET", "/api/v1/messages", base=MAILPIT)
        return page if page.get("total", 0) > 0 else None

    page = wait_for("an email in Mailpit", any_mail, timeout=180)
    return [m.get("Subject") for m in page.get("messages", [])]


def summary():
    print("\n=== End-to-end summary ===")
    for name, passed, detail in results:
        print(f"{'PASS' if passed else 'FAIL'}  {name}  ({detail})")


def main():
    os.makedirs(os.path.join(HERE, ".work"), exist_ok=True)
    token = sign_in()
    dns_xref = dns_credential(token)
    k8s_xref = k8s_credential(token)
    xref, serial = issue(token, dns_xref, k8s_xref)
    certificate_authorities(token)
    agents_page(token)
    discover(token, k8s_xref, serial)
    renewed = renew(token, xref, serial)
    subjects = email()
    expiry_alert()
    auto_renew(xref, renewed)
    token = admin_reset()
    reset_links_hidden(token)
    value = value_summary(token)
    print("Value summary:", {k: value[k] for k in ("minutesSaved", "renewals", "scheduledRenewals",
                                                   "automatedDeployments", "renewedBeforeExpiry")})
    summary()
    print("Emails:", subjects)


if __name__ == "__main__":
    main()
