#!/usr/bin/env python3
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

"""CertPing load test against the running end-to-end lab (see README.md, "Load test").

Phases (run one, or "all" in order):
  issue     issue N certificates for distinct names under lab.test, each deployed to Kubernetes
  renew     make all of them due at once and let the renewal job (every minute in the lab) renew them
  idle      K simulated agents long-poll the gateway with no work, after a baseline with none
  combined  K idle agents plus a renewal storm, to see whether idle polling slows real work

Every phase samples, every few seconds: docker stats of the CertPing container, CPU per process inside
it (server, agent, notifier, PostgreSQL), PostgreSQL transactions per second (each JdbcTemplate statement
outside a transaction is one), backend connections per owning process and state, and message_queue
depth per channel. Results go to .work/load-<phase>-<time>.json and a summary is printed.

The all-in-one image runs PostgreSQL in the same container as the server, so every number is for one box.
Standard library only (Python 3.9+).
"""
import argparse
import base64
import http.client
import json
import os
import random
import secrets
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = os.environ.get("CERTPING_E2E_URL", "http://localhost:8090")
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, ".work")
STATE = os.path.join(WORK, "load-state.json")
CONTAINER = os.environ.get("CERTPING_LOAD_CONTAINER", "certping-e2e-certping-1")
NAMESPACE = "load"
GATEWAY = "/api/v1/agent-gateway"


def log(msg):
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, STATE)


# ---------------------------------------------------------------- shell, psql, kubectl

def run(args, stdin=None, check=True, timeout=120):
    out = subprocess.run(args, capture_output=True, text=True, input=stdin, timeout=timeout)
    if check and out.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:6])} failed: {out.stderr.strip()[:500]}")
    return out.stdout


def psql(sql):
    return run(["docker", "exec", CONTAINER, "runuser", "-u", "postgres", "--",
                "psql", "-d", "certping", "-v", "ON_ERROR_STOP=1", "-tAc", sql]).strip()


def kubectl(*args, stdin=None):
    return run(["docker", "compose", "exec", "-T", "k3s", "kubectl", *args], stdin=stdin)


# ---------------------------------------------------------------- API

class Api:
    """Signs in once and reuses the token (sign-in is limited to 20 per 5 minutes per address)."""

    def __init__(self):
        self.token = None
        self.at = 0
        self.lock = threading.Lock()

    def login(self):
        with self.lock:
            if self.token and time.time() - self.at < 40 * 60:
                return self.token
            cache = os.path.join(WORK, "load-token.json")
            try:
                with open(cache) as f:
                    c = json.load(f)
                if time.time() - c["at"] < 40 * 60:
                    self.token, self.at = c["token"], c["at"]
                    return self.token
            except (OSError, ValueError, KeyError):
                pass
            pw = open(os.path.join(WORK, "admin-password")).read().strip()
            status, body = self._raw("POST", "/api/auth/login", None, {"identifier": "admin", "password": pw})
            if status != 200 or not body or "token" not in body:
                raise RuntimeError(f"login failed: {status} {body}")
            self.token, self.at = body["token"], time.time()
            with open(cache, "w") as f:
                json.dump({"token": self.token, "at": self.at}, f)
            return self.token

    def _raw(self, method, path, token, body, timeout=60):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = raw[:300].decode(errors="replace")
        return status, payload

    def call(self, method, path, body=None, ok=(200, 201, 202, 204)):
        status, payload = self._raw(method, path, self.login(), body)
        if status == 401:
            with self.lock:
                self.token = None
                try:
                    os.remove(os.path.join(WORK, "load-token.json"))
                except OSError:
                    pass
            status, payload = self._raw(method, path, self.login(), body)
        if status not in ok:
            raise ApiError(status, f"{method} {path} -> {status}: {str(payload)[:300]}")
        return payload


class ApiError(RuntimeError):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


api = Api()


# ---------------------------------------------------------------- sampler

# Runs inside the CertPing container (python3 is there for supervisord), so one docker exec per sample.
CONTAINER_PROBE = r'''
import json, os, subprocess
groups = {}
socks = {}
for pid in os.listdir("/proc"):
    if not pid.isdigit():
        continue
    try:
        cmd = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\0", b" ").decode(errors="replace")
        st = open("/proc/%s/stat" % pid).read()
    except OSError:
        continue
    f = st[st.rfind(")") + 2:].split()
    ticks, rss = int(f[11]) + int(f[12]), int(f[21]) * 4096
    if "server.jar" in cmd: g = "server"
    elif "agent.jar" in cmd: g = "agent"
    elif "notifier.jar" in cmd: g = "notifier"
    elif cmd.startswith("postgres") or "/postgres " in cmd: g = "postgres"
    else: g = "other"
    groups[pid] = [g, ticks, rss]
# docker exec has no ptrace capability, so sockets are matched to their owner by uid: the server runs as
# certping (the bundled agent too, but it never connects to PostgreSQL), the notifier as certping-notifier.
import pwd
owners = {}
for u, g in (("certping", "server"), ("certping-notifier", "notifier")):
    try:
        owners[str(pwd.getpwnam(u).pw_uid)] = g
    except KeyError:
        pass
ports = {}
for path in ("/proc/net/tcp", "/proc/net/tcp6"):
    try:
        for line in open(path).readlines()[1:]:
            p = line.split()
            if p[7] in owners:
                ports[int(p[1].split(":")[1], 16)] = owners[p[7]]
    except OSError:
        pass
sql = """select json_build_object(
 'xact', (select xact_commit + xact_rollback from pg_stat_database where datname = 'certping'),
 'tup', (select tup_returned + tup_fetched from pg_stat_database where datname = 'certping'),
 'act', (select coalesce(json_agg(json_build_object('port', client_port, 'state', state)), '[]') from pg_stat_activity
         where datname = 'certping' and pid <> pg_backend_pid()),
 'mq', (select coalesce(json_agg(json_build_object('c', channel, 's', status, 'n', n)), '[]') from
        (select channel, status, count(*) n from message_queue group by 1, 2) q))"""
out = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-d", "certping", "-tAc", sql],
                     capture_output=True, text=True).stdout.strip()
db = json.loads(out) if out else {}
# Connections busy in a statement, sampled 40 times over about one second (one snapshot misses short queries).
busy = """do $$ declare n int; mx int := 0; tot int := 0; begin
  for i in 1..40 loop
    perform pg_stat_clear_snapshot();
    select count(*) into n from pg_stat_activity where datname = 'certping' and state <> 'idle'
       and pid <> pg_backend_pid();
    mx := greatest(mx, n); tot := tot + n; perform pg_sleep(0.025);
  end loop;
  raise notice 'BUSY % %', mx, tot / 40.0; end $$"""
err = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-d", "certping", "-qc", busy],
                     capture_output=True, text=True).stderr
b = [l for l in err.splitlines() if "BUSY" in l]
busy_max, busy_avg = (float(x) for x in b[0].split("BUSY")[1].split()) if b else (None, None)
conns = {}
for a in db.get("act", []):
    owner = ports.get(a["port"], "other")
    key = owner + ":" + (a["state"] or "none")
    conns[key] = conns.get(key, 0) + 1
print(json.dumps({"cpu": groups, "xact": db.get("xact"), "tup": db.get("tup"), "conns": conns,
                  "busy_max": busy_max, "busy_avg": busy_avg, "mq": db.get("mq", [])}))
'''


def parse_size(s):
    s = s.strip()
    units = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "kB": 1 / 1000, "MB": 1, "GB": 1000, "B": 1 / 2 ** 20}
    for u in sorted(units, key=len, reverse=True):
        if s.endswith(u):
            return float(s[: -len(u)]) * units[u]
    return 0.0


class Sampler:
    def __init__(self, interval=5):
        self.interval = interval
        self.samples = []
        self.stats = []
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self._probe, daemon=True),
                        threading.Thread(target=self._docker_stats, daemon=True)]

    def start(self):
        for t in self.threads:
            t.start()
        return self

    def close(self):
        self.stop.set()
        for t in self.threads:
            t.join(15)

    def _probe(self):
        prev = None
        while not self.stop.is_set():
            t0 = time.time()
            try:
                out = run(["docker", "exec", "-i", CONTAINER, "python3", "-"], stdin=CONTAINER_PROBE, timeout=30)
                cur = json.loads(out)
                cur["t"] = time.time()
                if prev:
                    dt = cur["t"] - prev["t"]
                    # Per process, so a PostgreSQL backend that exits does not count as negative CPU. A process
                    # that started in the interval counts all its ticks. Ticks are 1/100 s: ticks/s == % of a core.
                    cpu, rss = {}, {}
                    for pid, (g, ticks, mem) in cur["cpu"].items():
                        before = prev["cpu"].get(pid)
                        cpu[g] = cpu.get(g, 0) + ticks - (before[1] if before and before[0] == g else 0)
                        rss[g] = rss.get(g, 0) + mem
                    cur["cpu_pct"] = {g: round(v / dt, 1) for g, v in cpu.items()}
                    cur["rss_mb"] = {g: round(v / 2 ** 20) for g, v in rss.items()}
                    cur["xact_s"] = round((cur["xact"] - prev["xact"]) / dt, 1)
                    cur["tup_s"] = round((cur["tup"] - prev["tup"]) / dt)
                    self.samples.append(cur)
                prev = cur
            except Exception as e:  # keep sampling through a hiccup
                log(f"sampler: {e}")
            self.stop.wait(max(0.5, self.interval - (time.time() - t0)))

    def _docker_stats(self):
        while not self.stop.is_set():
            try:
                out = run(["docker", "stats", "--no-stream", "--format", "{{json .}}", CONTAINER], timeout=30)
                s = json.loads(out.strip().splitlines()[0])
                self.stats.append({"t": time.time(), "cpu": float(s["CPUPerc"].rstrip("%")),
                                   "mem_mb": parse_size(s["MemUsage"].split("/")[0]),
                                   "limit_mb": parse_size(s["MemUsage"].split("/")[1])})
            except Exception as e:
                log(f"docker stats: {e}")
            self.stop.wait(1)

    def summary(self, t_from=0, t_to=1e12):
        ss = [s for s in self.samples if t_from <= s["t"] <= t_to]
        ds = [s for s in self.stats if t_from <= s["t"] <= t_to]
        out = {"samples": len(ss)}
        if ds:
            out["container_cpu_pct"] = {"avg": round(statistics.mean(d["cpu"] for d in ds), 1),
                                        "peak": max(d["cpu"] for d in ds)}
            out["container_mem_mb"] = {"avg": round(statistics.mean(d["mem_mb"] for d in ds)),
                                       "peak": round(max(d["mem_mb"] for d in ds)), "limit": round(ds[-1]["limit_mb"])}
        if ss:
            groups = sorted({g for s in ss for g in s["cpu_pct"]})
            out["process_cpu_pct"] = {g: {"avg": round(statistics.mean(s["cpu_pct"].get(g, 0) for s in ss), 1),
                                          "peak": max(s["cpu_pct"].get(g, 0) for s in ss)} for g in groups}
            out["process_rss_mb_peak"] = {g: max(s["rss_mb"].get(g, 0) for s in ss) for g in groups}
            out["pg_xact_per_s"] = {"avg": round(statistics.mean(s["xact_s"] for s in ss), 1),
                                    "peak": max(s["xact_s"] for s in ss)}
            out["pg_tuples_read_per_s_avg"] = round(statistics.mean(s["tup_s"] for s in ss))
            keys = sorted({k for s in ss for k in s["conns"]})
            out["pg_connections_peak"] = {k: max(s["conns"].get(k, 0) for s in ss) for k in keys}
            out["pg_connections_total_peak"] = max(sum(s["conns"].values()) for s in ss)
            out["server_conns_active_peak"] = max(s["conns"].get("server:active", 0)
                                                  + s["conns"].get("server:idle in transaction", 0) for s in ss)
            bs = [s for s in ss if s.get("busy_max") is not None]
            if bs:
                out["pg_busy_connections"] = {"peak": max(s["busy_max"] for s in bs),
                                              "avg": round(statistics.mean(s["busy_avg"] for s in bs), 2)}
            depth = {}
            for s in ss:
                per = {}
                for row in s["mq"]:
                    per[row["c"] + ":" + row["s"]] = per.get(row["c"] + ":" + row["s"], 0) + row["n"]
                for k, v in per.items():
                    depth[k] = max(depth.get(k, 0), v)
            out["queue_depth_peak"] = depth
        return out


def log_counts(since, prefix=None):
    """From the container log since `since`: 429s, redeliveries, and ACME orders per name (more than one = extra)."""
    import re
    out = subprocess.run(["docker", "logs", "--since", str(int(since)), CONTAINER], capture_output=True, text=True)
    lines = (out.stdout + out.stderr).splitlines()
    orders = {}
    c = {"http_429_lines": 0, "redeliveries": 0, "pool_timeouts": 0, "errors": 0}
    for l in lines:
        if "HTTP 429" in l or "status=429" in l:
            c["http_429_lines"] += 1
        if re.search(r"deliveryCount=[1-9]", l):
            c["redeliveries"] += 1
        if "Connection is not available" in l:
            c["pool_timeouts"] += 1
        if " ERROR " in l:
            c["errors"] += 1
        m = re.search(r"LE order created for domain=(\S+?),", l)
        if m and (prefix is None or m.group(1).startswith(prefix)):
            orders[m.group(1)] = orders.get(m.group(1), 0) + 1
    c["acme_orders"] = sum(orders.values())
    c["names_with_extra_orders"] = sum(1 for n in orders.values() if n > 1)
    c["extra_orders"] = sum(n - 1 for n in orders.values() if n > 1)
    return c


def dead_letters():
    return int(psql("select count(*) from message_queue where status = 'DEAD'") or 0)


# ---------------------------------------------------------------- lab setup for the load

def ensure_credentials(state):
    if state.get("dns_xref") and state.get("k8s_xref"):
        return state
    key = "cpk_live_lab12345" + secrets.token_hex(12)
    dns = api.call("POST", "/api/v1/credentials/dns", {
        "provider": "CERTPING", "description": "Load DNS", "credJson": {"apiKey": key},
        "configJson": {"tokenId": 1, "tokenPrefix": "cpk_live_lab12345", "expiresAt": "2030-01-01T00:00:00Z"}})
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
    sa_token = kubectl("-n", NAMESPACE, "create", "token", "certping", "--duration=720h").strip()
    ca = run(["docker", "compose", "exec", "-T", "k3s", "cat", "/var/lib/rancher/k3s/server/tls/server-ca.crt"])
    k8s = api.call("POST", "/api/v1/credentials/deployment", {
        "provider": "KUBERNETES_SECRETS", "description": "Load cluster",
        "configJson": {"authMethod": "SA_TOKEN", "clusterName": "lab", "namespaces": [NAMESPACE]},
        "credJson": {"apiServer": "https://k3s:6443", "bearerToken": sa_token, "caCertPem": ca}})
    state["dns_xref"], state["k8s_xref"] = dns["credentialXref"], k8s["credentialXref"]
    save_state(state)
    return state


def progress_sql(prefix, since, flow):
    # Names are "<prefix>NNNN.lab.test"; the prefix has no LIKE wildcards.
    return f"""
with u as (select id from user_domain_certificate where domain like '{prefix}%' and not is_deleted),
c as (select c.* from certificates c join u on u.id = c.user_domain_cert_id where not c.is_deleted),
d as (select d.* from deployments d join u on u.id = d.user_domain_cert_id
      where d.flow_type = '{flow}' and d.created_at >= to_timestamp({since}))
select json_build_object(
 'names', (select count(*) from u),
 'status', (select coalesce(json_object_agg(status, n), '{{}}') from (select status, count(*) n from c group by 1) s),
 'active_new', (select count(distinct user_domain_cert_id) from c where status = 'ACTIVE'
                and created_at >= to_timestamp({since})),
 'deployed', (select count(distinct user_domain_cert_id) from d where status = 'SUCCESS'),
 'deploy_status', (select coalesce(json_object_agg(status, n), '{{}}') from (select status, count(*) n from d group by 1) s),
 'deploy_errors', (select coalesce(json_object_agg(k, n), '{{}}') from (select coalesce(error_code, '?') || ': '
                   || left(coalesce(error_detail, ''), 160) k, count(*) n from d where status not in ('SUCCESS', 'PENDING',
                   'PUBLISHED', 'IN_PROGRESS') group by 1) s),
 'cert_errors', (select coalesce(json_object_agg(k, n), '{{}}') from (select status || ' ' || coalesce(last_error_code, '?')
                 || ': ' || left(coalesce(last_error_message, ''), 160) k, count(*) n from c
                 where last_error_code is not null and updated_at >= to_timestamp({since}) group by 1) s))
"""


def track(name, prefix, since, flow, target, timeout, stall, done_fn=None):
    """Polls the database until `target` names are deployed for `flow`, or no progress for `stall` seconds."""
    series = []
    last_change, last_key = time.time(), None
    deadline = since + timeout
    while True:
        p = json.loads(psql(progress_sql(prefix, since, flow)))
        p["t"] = round(time.time() - since)
        series.append(p)
        # Progress is new deployments or certificates; status churn alone (the retry job reworking a few
        # failures every few minutes) does not keep a finished phase open.
        key = (p["deployed"], p["active_new"])
        if key != last_key:
            last_key, last_change = key, time.time()
        log(f"{name}: t={p['t']}s active(new)={p['active_new']} deployed={p['deployed']}/{target} "
            f"status={p['status']} deploys={p['deploy_status']}")
        if p["deployed"] >= target:
            break
        if time.time() > deadline:
            log(f"{name}: timed out after {timeout}s")
            break
        if os.path.exists(os.path.join(WORK, "load-stop")):
            os.remove(os.path.join(WORK, "load-stop"))
            log(f"{name}: .work/load-stop found, stopping and reporting")
            break
        if time.time() - last_change > stall:
            log(f"{name}: no progress for {stall}s, stopping")
            break
        time.sleep(10)
    return series


def throughput(series, target):
    """Deployed per minute between 10% and 90% of the target (steady state), and overall."""
    def first(n):
        return next((p["t"] for p in series if p["deployed"] >= n), None)
    t10, t90, t100 = first(max(1, target // 10)), first(max(1, target * 9 // 10)), first(target)
    steady = round((target * 0.8) / ((t90 - t10) / 60), 1) if t10 is not None and t90 and t90 > t10 else None
    return {"t_first_s": first(1), "t_10pct_s": t10, "t_90pct_s": t90, "t_all_s": t100,
            "steady_per_min": steady,
            "overall_per_min": round(series[-1]["deployed"] / (series[-1]["t"] / 60), 1) if series[-1]["t"] else None}


def report(phase, result):
    os.makedirs(WORK, exist_ok=True)
    path = os.path.join(WORK, f"load-{phase}-{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w") as f:
        json.dump(result, f, indent=1)
    printable = {k: v for k, v in result.items() if k not in ("series", "samples")}
    print(f"\n=== {phase} ===\n" + json.dumps(printable, indent=1), flush=True)
    log(f"saved {path}")


# ---------------------------------------------------------------- phase 1: bulk issue

def phase_issue(args):
    state = ensure_credentials(load_state())
    prefix = args.prefix or f"ld{int(time.time()) % 100000}-"
    state.update({"prefix": prefix, "n": args.n})
    save_state(state)
    dl0 = dead_letters()
    sampler = Sampler().start()
    log(f"issue: submitting {args.n} certificates as {prefix}NNNN.lab.test, {args.submit_concurrency} at a time")
    failures, latencies, statuses = {}, [], {}
    lock = threading.Lock()

    def submit(i):
        name = f"{prefix}{i:04d}"
        body = {"domain": f"{name}.lab.test", "wildcard": False, "san": False, "caProvider": "LETS_ENCRYPT",
                "dnsCredentialXref": state["dns_xref"], "deploymentTargets": [state["k8s_xref"]],
                "deploymentTargetConfigs": [{"deploymentCredentialXref": state["k8s_xref"],
                                             "config": {"nsSecretMap": [{NAMESPACE: f"{name}-tls"}]}}]}
        for attempt in range(5):
            t0 = time.time()
            try:
                api.call("POST", "/api/v1/certs/issue", body)
                with lock:
                    latencies.append(time.time() - t0)
                    statuses["202"] = statuses.get("202", 0) + 1
                return
            except ApiError as e:
                with lock:
                    statuses[str(e.status)] = statuses.get(str(e.status), 0) + 1
                if e.status in (429, 502, 503, 504):
                    time.sleep(2 ** attempt)
                    continue
                with lock:
                    failures[str(e)[:200]] = failures.get(str(e)[:200], 0) + 1
                return
            except Exception as e:
                with lock:
                    failures[str(e)[:200]] = failures.get(str(e)[:200], 0) + 1
                return

    t0 = time.time()
    with ThreadPoolExecutor(args.submit_concurrency) as pool:
        list(pool.map(submit, range(args.n)))
    submit_s = time.time() - t0
    submitted = sum(1 for _ in latencies)
    log(f"issue: submitted {submitted}/{args.n} in {submit_s:.1f}s, responses {statuses}")
    series = track("issue", prefix, t0, "AUTO_POST_ISSUANCE", submitted, args.timeout, args.stall)
    t_end = time.time()
    secrets_in_k8s = len([l for l in kubectl("-n", NAMESPACE, "get", "secrets", "--no-headers").splitlines()
                          if l.startswith(prefix)])
    sampler.close()
    lat = sorted(latencies)
    report("issue", {
        "n": args.n, "prefix": prefix, "submitted": submitted, "submit_s": round(submit_s, 1),
        "submit_per_s": round(submitted / submit_s, 1) if submit_s else None,
        "submit_latency_s": {"p50": round(lat[len(lat) // 2], 3), "p95": round(lat[int(len(lat) * .95)], 3),
                             "max": round(lat[-1], 3)} if lat else None,
        "submit_responses": statuses, "submit_failures": failures,
        "duration_s": round(t_end - t0), "final": series[-1], "throughput": throughput(series, submitted),
        "k8s_secrets": secrets_in_k8s, "dead_letters_new": dead_letters() - dl0,
        "log": log_counts(t0, prefix),
        "load": sampler.summary(t0, t_end), "series": series})


# ---------------------------------------------------------------- phase 2: renewal storm

def renewal_storm(args, label):
    state = load_state()
    prefix = state.get("prefix")
    if not prefix:
        raise SystemExit("run the issue phase first")
    dl0 = dead_letters()
    t0 = time.time()
    moved = psql(f"""
with s as (update renewal_schedule rs set renewal_eligible_at = now() - interval '1 minute', next_attempt_at = null
             from certificates c, user_domain_certificate u
            where rs.certificate_xref = c.certificate_xref and c.user_domain_cert_id = u.id
              and u.domain like '{prefix}%' and c.status = 'ACTIVE' and rs.enabled and not rs.is_deleted
           returning rs.id) select count(*) from s""")
    moved = int(moved.splitlines()[-1])
    log(f"{label}: {moved} renewal schedules made due; the renewal job runs at the next minute")
    series = track(label, prefix, t0, "AUTO_POST_RENEWAL", moved, args.timeout, args.stall)
    t_end = time.time()
    return {"due": moved, "duration_s": round(t_end - t0), "final": series[-1],
            "throughput": throughput(series, moved), "dead_letters_new": dead_letters() - dl0,
            "log": log_counts(t0, prefix), "series": series}, t0, t_end


def phase_renew(args):
    sampler = Sampler().start()
    result, t0, t1 = renewal_storm(args, "renew")
    sampler.close()
    result["load"] = sampler.summary(t0, t1)
    report("renew", result)


# ---------------------------------------------------------------- phase 3: idle agents

def agent_tokens(k, orgs):
    """K agent tokens spread over `orgs` organizations of their own (so they never take real work)."""
    state = load_state()
    pool = state.setdefault("agent_tokens", [])
    org_ids = state.setdefault("idle_orgs", [])
    while len(org_ids) < orgs:
        n = len(org_ids) + 1
        slug = f"load-idle-{n}"
        try:
            org = api.call("POST", "/api/v1/organizations", {"name": f"Load idle {n}", "domain": f"idle{n}.lab.test",
                                                            "slug": slug})
        except ApiError:
            org = api.call("GET", f"/api/v1/organizations/slug/{slug}")
        org_ids.append(org["id"])
        save_state(state)
    wanted = [o for o in org_ids[:orgs]]
    have = [t for t in pool if t["org"] in wanted]
    i = len(pool)
    while len(have) < k:
        org = wanted[len(have) % len(wanted)]
        created = api.call("POST", f"/api/v1/agent-tokens?organizationId={org}", {"name": f"load-idle-{i}"})
        t = {"org": org, "value": created["value"]}
        pool.append(t)
        have.append(t)
        i += 1
        if i % 50 == 0:
            save_state(state)
    save_state(state)
    return have[:k]


class IdleAgents:
    """K threads, each one agent: long-poll receive exactly as GatewayClient does, settle anything received."""

    def __init__(self, tokens, wait_seconds=20):
        self.tokens = tokens
        self.wait = wait_seconds
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.status = {}
        self.latency = []      # (t, seconds) per receive
        self.received = 0
        self.errors = {}
        self.threads = []
        self.probe_lat = []    # whoami latency during the phase

    def start(self):
        for t in self.tokens:
            th = threading.Thread(target=self._agent, args=(t["value"],), daemon=True)
            th.start()
            self.threads.append(th)
            time.sleep(0.02)  # spread the polls like agents that started at different times
        threading.Thread(target=self._probe, daemon=True).start()
        return self

    def _conn(self):
        host = BASE.split("://", 1)[1]
        return http.client.HTTPConnection(host, timeout=self.wait + 40)

    def _request(self, conn, method, path, token, body=None):
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()

    def _agent(self, token):
        conn = self._conn()
        path = f"{GATEWAY}/messages?queue=inbound&max=1&waitSeconds={self.wait}"
        backoff = 1
        while not self.stop.is_set():
            t0 = time.time()
            try:
                status, raw = self._request(conn, "GET", path, token)
            except Exception as e:
                with self.lock:
                    self.errors[type(e).__name__] = self.errors.get(type(e).__name__, 0) + 1
                conn.close()
                conn = self._conn()
                self.stop.wait(backoff)
                backoff = min(30, backoff * 2)
                continue
            dt = time.time() - t0
            with self.lock:
                self.status[status] = self.status.get(status, 0) + 1
                self.latency.append((t0, dt))
            if status != 200:
                self.stop.wait(backoff)  # the agent backs off the same way
                backoff = min(30, backoff * 2)
                continue
            backoff = 1
            for m in json.loads(raw or b"[]"):
                with self.lock:
                    self.received += 1
                try:
                    self._request(conn, "POST", f"{GATEWAY}/messages/{m['id']}/complete?queue=inbound", token,
                                  {"lockToken": m["lockToken"]})
                except Exception:
                    conn.close()
                    conn = self._conn()
        conn.close()

    def _probe(self):
        conn = self._conn()
        token = self.tokens[0]["value"]
        while not self.stop.is_set():
            t0 = time.time()
            try:
                self._request(conn, "GET", f"{GATEWAY}/whoami", token)
                self.probe_lat.append((t0, time.time() - t0))
            except Exception:
                conn.close()
                conn = self._conn()
            self.stop.wait(2)

    def close(self):
        self.stop.set()
        for th in self.threads:
            th.join(self.wait + 45)

    def summary(self, t_from=0, t_to=1e12):
        lat = sorted(d for t, d in self.latency if t_from <= t <= t_to)
        probe = sorted(d for t, d in self.probe_lat if t_from <= t <= t_to)

        def pct(xs, q):
            return round(xs[min(len(xs) - 1, int(len(xs) * q))], 3) if xs else None
        return {"agents": len(self.tokens), "orgs": len({t["org"] for t in self.tokens}),
                "receives": len(lat), "status": {str(k): v for k, v in self.status.items()},
                "errors": self.errors, "messages_received": self.received,
                "receive_s": {"p50": pct(lat, .5), "p95": pct(lat, .95), "p99": pct(lat, .99),
                              "max": lat[-1] if lat else None,
                              "returned_early_under_19s": sum(1 for d in lat if d < self.wait - 1)},
                "whoami_s": {"p50": pct(probe, .5), "p95": pct(probe, .95), "max": probe[-1] if probe else None}}


def phase_idle(args):
    tokens = agent_tokens(args.k, args.idle_orgs)
    sampler = Sampler().start()
    log(f"idle: baseline {args.baseline}s with no simulated agents")
    b0 = time.time()
    time.sleep(args.baseline)
    b1 = time.time()
    log(f"idle: starting {len(tokens)} idle agents for {args.duration}s")
    agents = IdleAgents(tokens).start()
    ramp = time.time()
    time.sleep(args.duration)
    a1 = time.time()
    agents.close()
    sampler.close()
    base, load = sampler.summary(b0, b1), sampler.summary(ramp + 25, a1)
    result = {"k": len(tokens), "duration_s": args.duration, "baseline": base, "idle": load,
              "agents": agents.summary(ramp, a1), "log": log_counts(b0)}
    try:
        dx = load["pg_xact_per_s"]["avg"] - base["pg_xact_per_s"]["avg"]
        dcpu = {g: round(load["process_cpu_pct"][g]["avg"] - base["process_cpu_pct"].get(g, {"avg": 0})["avg"], 1)
                for g in ("server", "postgres")}
        result["per_agent"] = {"pg_xact_per_s": round(dx / len(tokens), 2),
                               "server_cpu_pct": round(dcpu["server"] / len(tokens), 3),
                               "postgres_cpu_pct": round(dcpu["postgres"] / len(tokens), 3)}
        result["projected"] = {str(n): {"pg_xact_per_s": round(dx / len(tokens) * n),
                                        "server_plus_pg_cores": round((dcpu["server"] + dcpu["postgres"])
                                                                      / len(tokens) * n / 100, 2)}
                               for n in (1000, 5000)}
    except (KeyError, TypeError, ZeroDivisionError):
        pass
    report("idle", result)


# ---------------------------------------------------------------- phase 4: idle agents plus renewal storm

def phase_combined(args):
    tokens = agent_tokens(args.k, args.idle_orgs)
    sampler = Sampler().start()
    log(f"combined: starting {len(tokens)} idle agents, then the renewal storm")
    agents = IdleAgents(tokens).start()
    time.sleep(30)
    result, t0, t1 = renewal_storm(args, "combined")
    agents.close()
    sampler.close()
    result["load"] = sampler.summary(t0, t1)
    result["agents"] = agents.summary(t0, t1)
    report("combined", result)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("phase", choices=["issue", "renew", "idle", "combined", "all"])
    p.add_argument("-n", type=int, default=1000, help="certificates to issue (issue)")
    p.add_argument("--prefix", help="name prefix for the issued certificates (default: a fresh one)")
    p.add_argument("--submit-concurrency", type=int, default=16, help="parallel issue requests")
    p.add_argument("-k", type=int, default=200, help="simulated idle agents (idle, combined)")
    p.add_argument("--idle-orgs", type=int, default=1, help="organizations the idle agents are spread over")
    p.add_argument("--duration", type=int, default=300, help="idle phase length in seconds")
    p.add_argument("--baseline", type=int, default=60, help="seconds measured before the idle agents start")
    p.add_argument("--timeout", type=int, default=7200, help="longest wait for a phase to finish, seconds")
    p.add_argument("--stall", type=int, default=600, help="stop a phase after this long with no progress")
    args = p.parse_args()
    os.chdir(HERE)
    os.makedirs(WORK, exist_ok=True)
    phases = ["issue", "renew", "idle", "combined"] if args.phase == "all" else [args.phase]
    for ph in phases:
        {"issue": phase_issue, "renew": phase_renew, "idle": phase_idle, "combined": phase_combined}[ph](args)


if __name__ == "__main__":
    main()
