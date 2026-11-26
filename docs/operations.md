# Operations

How-to guides for running CertPing: upgrades, backups, health checks, logs, growth and
troubleshooting. Installation is in [self-hosting.md](self-hosting.md), and every setting is in
[configuration.md](configuration.md).

## Upgrade CertPing

Every release is a new set of images. The server runs the database migrations (Flyway) when it
starts, before it reports ready. Migrations only go forward, so the way back is a restore of the
backup you took before the upgrade, with the old images.

1. Read the [release notes](https://github.com/certping-labs/certping/releases) for every version
   between yours and the target.
2. [Back up](#back-up-and-restore).
3. Change the version and restart, as in the section for your kit below.
4. Check that the server [reports ready](#check-that-the-server-is-healthy) and that agents show a
   recent **Last seen** on the **Agents** page.

Upgrade the server first. An agent one version behind keeps working until you update it, and
agent tokens survive upgrades. Skipping versions works, because every migration in between runs
at start. A very large jump is still easier in steps, so that each release's notes apply to the
state you are in.

### Upgrade the all-in-one

```sh
docker pull ghcr.io/certping-labs/certping:<new version>
docker stop certping && docker rm certping
docker run -d --name certping -p 80:80 -p 443:443 -v certping:/var/lib/certping \
  -e CERTPING_URL=https://certping.example.com \
  ghcr.io/certping-labs/certping:<new version>
```

Pass the same `-e` settings you used before. More detail is in the
[all-in-one README](../deploy/all-in-one/README.md#upgrade).

### Upgrade the Compose kit

```sh
cd deploy/compose
./setup.sh --upgrade
sed -i.bak "s/^CERTPING_VERSION=.*/CERTPING_VERSION='<new version>'/" .env
grep -q '^CERTPING_VERSION=' .env || echo "CERTPING_VERSION='<new version>'" >> .env
docker compose pull && docker compose up -d
```

`./setup.sh --upgrade` adds the keys a newer release needs (for example `REDIS_PASSWORD`) to an
existing `.env`. It never changes or removes a key that is already there. Notes on Valkey and
older `.env` files are in the [Compose README](../deploy/compose/README.md#operations).

### Upgrade a Helm install

```sh
helm upgrade certping deploy/charts/certping -n certping -f your-values.yaml --set image.tag=<new version>
helm upgrade edge deploy/charts/certping-agent -n certping-agent -f your-agent-values.yaml --set image.tag=<new version>
```

Run the server chart first, then each agent release. More detail is in the
[chart README](../deploy/charts/certping/README.md#upgrade).

## Back up and restore

Three parts make a restorable backup:

| Part | Why |
| --- | --- |
| PostgreSQL | Every record, the job queue, password hashes and the audit log. |
| The generated secrets (`config.env`, `.env` or the `certping` Secret) | The password pepper and `CERTPING_LOCAL_SECRET_KEY` decrypt what the database and the secrets directory hold. A backup without them cannot be restored. |
| The `LOCAL` secrets directory | The bundled agent's private keys, ACME account keys and pasted credentials, encrypted with `CERTPING_LOCAL_SECRET_KEY`. |

Valkey needs no backup. Remote agents keep their keys in your cloud secret manager; back that up
with your cloud's own tools. Test a restore before you need one.

Every backup below contains the installation's secrets (`config.env` or `.env`, or a copy of the
secrets volume). Anyone with the archive can decrypt the stored keys and credentials, so store it
encrypted and limit who can read it. Each block starts with `umask 077`, so the files you write on
the host are readable by you only.

### Back up the all-in-one

Everything is on one volume (`/var/lib/certping`: `postgres/`, `secrets/`, `caddy/`, `valkey/`,
`config.env`). If you can stop the container for a minute, archive the whole volume. The archive
holds the database, `config.env` and the secrets directory together, so they always match. This
is the method we recommend:

```sh
umask 077
docker stop certping
docker run --rm -v certping:/data busybox tar czf - -C /data . > certping.tgz
docker start certping
```

### Restore the all-in-one from a volume archive

Remove or rename the old container first if it still exists. Then restore into an empty volume
and start the same image version you backed up:

```sh
docker volume create certping-restored
docker run --rm -i -v certping-restored:/data busybox tar xzf - -C /data < certping.tgz
docker run -d --name certping -p 80:80 -p 443:443 -v certping-restored:/var/lib/certping \
  -e CERTPING_URL=https://certping.example.com ghcr.io/certping-labs/certping:0.0.1-beta
```

### Back up the all-in-one without stopping it

If the container must keep running, take a database dump plus `config.env` and `secrets/`:

```sh
umask 077
docker exec certping gosu postgres pg_dump -Fc -d certping > certping.dump
docker exec certping tar czf - -C /var/lib/certping config.env secrets > certping-secrets.tgz
```

### Restore a database dump into the all-in-one

This restores a dump into the same installation, with the same `config.env`. Stop the three
application programs, replace the `public` schema, restore without `--clean`, and start them
again. `pg_restore --clean` does not work here: it fails on the primary keys that the
`audit_events` partitions inherit. The database and its `public` schema belong to the `certping`
role, which the entrypoint creates.

```sh
docker exec certping supervisorctl stop server agent notifier
docker exec -i certping gosu postgres psql -v ON_ERROR_STOP=1 -d certping <<'SQL'
DROP SCHEMA public CASCADE;
CREATE SCHEMA public AUTHORIZATION certping;
GRANT USAGE ON SCHEMA public TO PUBLIC;
SQL
docker exec -i certping gosu postgres pg_restore -d certping < certping.dump
docker exec certping supervisorctl start server notifier agent
```

`DROP SCHEMA` prints a long `drop cascades to ...` list; that is expected. `pg_restore` should
exit with status 0. The server is ready again about a minute later.

If you also lost `secrets/`, restore it before starting the programs:

```sh
docker exec -i certping tar xzf - -C /var/lib/certping secrets < certping-secrets.tgz
docker exec certping chown -R certping:certping /var/lib/certping/secrets
```

### Back up and restore the Compose kit

Back up the database, the secrets volume and `.env`:

```sh
umask 077
cd deploy/compose
docker compose exec -T postgres pg_dump -U certping -Fc certping > certping.dump
docker run --rm -v certping_agent-secrets:/data busybox tar czf - -C /data . > agent-secrets.tgz
cp .env env.backup
```

Restore, with the `.env` of the same installation in place. As on the all-in-one, replace the
`public` schema and restore without `--clean`:

```sh
docker compose stop server notifier agent
docker compose exec -T postgres psql -U certping -d certping -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA public CASCADE;
CREATE SCHEMA public AUTHORIZATION certping;
GRANT USAGE ON SCHEMA public TO PUBLIC;
SQL
docker compose exec -T postgres pg_restore -U certping -d certping < certping.dump
docker run --rm -i -v certping_agent-secrets:/data busybox tar xzf - -C /data < agent-secrets.tgz
docker compose start server notifier agent
```

The volume names start with `certping_` because the Compose project is named `certping`. For a
full offline backup instead, run `docker compose stop` and archive the `certping_postgres-data`
and `certping_agent-secrets` volumes the same way, together with `.env`.

### Back up a Helm install

Back up the external PostgreSQL with your database's tools, the bundled agent's secrets volume
(the PVC whose name ends in `-agent-secrets`) with your volume snapshot tool, and the `certping`
Secret:

```sh
umask 077
kubectl -n certping get secret certping -o yaml > certping-secret.yaml
```

That file holds every generated secret; store it encrypted. A dump made with `pg_dump` restores
the same way as for Compose: replace the `public` schema, then `pg_restore` without `--clean`.

## Check that the server is healthy

| Endpoint | Where | Auth | What it says |
| --- | --- | --- | --- |
| `/actuator/health`, `/actuator/health/liveness`, `/actuator/health/readiness` | Server, port 8080 | None | `UP` or `DOWN` only, no details. Readiness is up once migrations are done. |
| `/actuator/info` | Server, port 8080 | None | Application information, which can be empty. |
| `/actuator/health/liveness`, `/actuator/health/readiness` | Agent and notifier, their HTTP port | None | Used by the container health checks and the Helm probes. |
| `/api/v1/public/status` | Through the public URL | None | The state of CertPing's components, from the last completed checks. |
| `/api/v1/deployment-info` | Through the public URL | None | Basic installation information the login page reads. The cheapest check that CertPing answers. |

The proxy in the kits sends only `/api/*`, `/.well-known/*` and the sign-in callback paths to the
server, so `/actuator/*` is not reachable through the public URL. Check it from inside:

```sh
docker exec certping curl -fsS http://127.0.0.1:8080/actuator/health/readiness        # all-in-one
docker compose exec server curl -fsS http://localhost:8080/actuator/health/readiness  # Compose
```

### If you want metrics and traces

There is no Prometheus endpoint in v0.1; the services expose only the `health` and `info`
actuator endpoints. If you use Compose, the server, agent and notifier images include the
OpenTelemetry Java agent: set `OTEL_JAVAAGENT_ENABLED=true` and `OTEL_EXPORTER_OTLP_ENDPOINT` in
`.env`. The all-in-one image does not load the OpenTelemetry agent, and the Helm chart turns it
off.

### Watch the queue and the agents

The Overview page lists what needs attention. To get an email when jobs pile up or land in the
dead-letter queue, list the message queue channels to watch; the job checks them every 5 minutes
and mails the Platform Super Admins on a breach and again on recovery. Set the list with
`SPRING_APPLICATION_JSON` or an extra configuration file (thresholds are in
[configuration.md](configuration.md)):

```yaml
certping:
  alerts:
    queue-depth:
      entities:
        - name: cert-agent-outbound   # results from agents
          active-threshold: 500       # optional, per channel
        - name: notifications
          dlq-threshold: 1
```

Agents send a heartbeat every 5 minutes, and after two missed heartbeats the server treats an
agent as stale.

## Read the logs

| Kit | Command |
| --- | --- |
| All-in-one | `docker logs -f certping` (every service in one stream) |
| Compose | `docker compose logs -f server agent notifier` |
| Helm | `kubectl -n certping logs deploy/certping-server -c server` (and `-c agent` for the bundled agent), for a release named `certping` |

Server and agent lines carry `[req=... corr=... msg=... org=...]`, so one request can be followed
from the server to the agent. Log levels: [configuration.md](configuration.md#logging).

## Plan for more certificates

In the end-to-end lab, one all-in-one container limited to 4 GB of memory, with its bundled agent
and Pebble as the CA, issued or renewed 1,000 certificates, each deployed to k3s, in about 3 to 4
minutes. That is roughly 250 to 330 a minute, and the limit was the agent's 8 concurrent jobs. With 200
idle agents connected, each caused about 0.8 database queries a second. These are lab numbers for
one container sharing its CPUs between PostgreSQL, the server, the agent and the notifier, with a
CA and DNS server that answer at once. Real CAs and DNS providers are slower and have rate limits.

### Run the load test yourself

Build the image, start the lab, then run `load.py`:

```sh
make images
cd deploy/e2e-lab
./run.sh
python3 load.py issue -n 1000
python3 load.py renew
python3 load.py idle -k 200
python3 load.py combined -k 200
```

Each phase prints a summary and writes the full samples to `.work/load-<phase>-<time>.json`.
Options are in [deploy/e2e-lab/README.md](../deploy/e2e-lab/README.md#load-test).

### If you need more throughput

If jobs queue up behind one agent, raise `CERTPING_AGENT_MAX_CONCURRENT_JOBS` on the agent and
`CERTPING_TRANSPORT_MAX_CONCURRENT_POLLS_PER_TOKEN` on the server together, or add agents with
their own tokens ([agents.md](agents.md#sizing-and-concurrency)). Most job time is spent waiting
on CAs and DNS, so more job slots help until a provider's rate limit is reached.

If you add server replicas or notifiers, check database connections. The server pool is 40
(`DB_POOL_SIZE`), and PostgreSQL's `max_connections` must cover every server replica's pool plus
10 per notifier, with headroom.

If you run more than one server replica on Helm, set `bundledAgent.enabled: false` and run agents
with the `certping-agent` chart. The bundled agent's `LOCAL` store is a ReadWriteOnce volume
shared with one server pod.

For Compose, 2 vCPU and 4 GB of memory is the documented starting point for a few thousand
certificates.

## Rate limits

| Limit | Default | Setting | Answer |
| --- | --- | --- | --- |
| Sign-in, MFA, forgot and reset password, SSO code exchange | 20 requests per endpoint per client address per 5 minutes | `CERTPING_RATE_LIMIT_AUTH_*` | `429`, code `RATE_LIMITED`, `Retry-After` |
| Failed sign-ins per account | 5, then locked 15 minutes | `APP_AUTH_LOCKOUT_MAX_FAILED_ATTEMPTS`, `APP_AUTH_LOCKOUT_DURATION` | Sign-in refused, audit reason `ACCOUNT_LOCKED` |
| Open long polls per agent token, per server | 8 | `CERTPING_TRANSPORT_MAX_CONCURRENT_POLLS_PER_TOKEN` | `429` |
| Polls per agent token per minute | 1200 | `CERTPING_TRANSPORT_MAX_REQUESTS_PER_TOKEN_PER_MINUTE` | `429` with `Retry-After` |
| Other gateway calls per agent token per minute | 6000 | `CERTPING_TRANSPORT_MAX_SETTLE_REQUESTS_PER_TOKEN_PER_MINUTE` | `429` with `Retry-After` |
| Messages waiting per organization | 10000 | `CERTPING_TRANSPORT_MAX_WAITING_MESSAGES_PER_ORGANIZATION` | `429` |
| Audit exports per organization | 10 an hour, 10000 rows each | `CERTPING_AUDIT_EXPORTS_PER_HOUR`, `CERTPING_AUDIT_EXPORT_MAX_ROWS` | `EXPORT_TOO_LARGE` or a `429` |

The rate limiter counts per client address. Behind a proxy, make sure the server sees the real
address ([self-hosting.md](self-hosting.md#running-behind-your-own-reverse-proxy)), or every user
shares one counter.

## Troubleshooting

Failed issuance, renewal and deployment show a message and an error code on the certificate and
in **Deployments**. The agent log has the detail. Permanent failures (such as a rejected
credential) are not retried; temporary ones are retried on their own
([architecture.md](architecture.md#the-job-queue)).

### If you cannot sign in

| Symptom | Cause and fix |
| --- | --- |
| `certping-admin` says `No /var/lib/certping/config.env yet: the container has not started once.` | The entrypoint has not run yet. Wait a few seconds and run it again. |
| Every page fails; the API answers `403` with `PASSWORD_CHANGE_REQUIRED` | The account must change its password first: Organization & Access, Your account. |
| `429 Too Many Requests` with code `RATE_LIMITED` on sign-in | More than 20 attempts from one address in 5 minutes. Wait for `Retry-After`. If many users hit it together, the server sees the proxy's address instead of theirs; see [Rate limits](#rate-limits). |
| "The account is locked after too many failed attempts" | 5 failed sign-ins lock the account for 15 minutes. |
| Lost admin password | All-in-one: `docker exec certping certping-admin reset-password admin` prints a reset link valid for one hour. Compose and Helm: use **Reset it by email** under the login form, which needs email configured. There is no reset helper for those kits in 0.0.1-beta. |

### If issuance fails with a DNS or ACME error

| Code | Meaning and fix |
| --- | --- |
| `DNS_PROPAGATION_TIMEOUT` | The TXT record was created but never appeared on the domain's authoritative nameservers. Usually the zone is served by other nameservers than the account the credential belongs to (check `dig NS example.com`), or the agent cannot reach the nameservers on port 53. |
| `DNS_ZONE_NOT_FOUND` | The connected DNS account has no zone for this domain, or the credential cannot see it. |
| `DNS_AUTH_FAILED`, `DNS_CREDENTIAL_INVALID` | The provider rejected the credential, or a required field is empty. Re-enter it. |
| `DNS_NS_LOOKUP_FAILED` | The domain has no working nameservers. |
| `DNS_PROVIDER_THROTTLED` | The DNS provider is rate-limiting. The agent retries. |
| `ACME_RATE_LIMITED` | The CA's rate limit. Wait; for tests, use Let's Encrypt staging. |
| `ACME_CHALLENGE_INVALID`, `ACME_ORDER_INVALID` | The CA could not validate, or refused the names. Check the spelling and that the domain resolves publicly. |
| `ACME_ACCOUNT_LOAD_FAILED`, `ACME_ACCOUNT_CREATE_FAILED` | The agent could not load or register its ACME account on the configured directory. Check that `ACME_DIRECTORY_URL` is right and reachable, and that the CA accepts `ACME_ACCOUNT_EMAIL`. |
| `ACME_EAB_INCOMPLETE` | Only one of `ACME_EAB_KEY_ID` and `ACME_EAB_HMAC_KEY` is set on the agent. Set both, or neither. |
| `ACME_NETWORK_ERROR` | The agent cannot reach the ACME directory: firewall, proxy or an untrusted private CA. |
| `PKIX path building failed` in the log | Java does not trust the CA's TLS certificate (a private ACME CA or a TLS-inspecting proxy). Give the CA as a PEM file: on the all-in-one, mount it and set `CERTPING_EXTRA_CA_CERTS=/path/in/container.pem` (the log then says `trusting N extra CA certificate(s)`); in Compose, set `CERTPING_EXTRA_CA_CERTS` in `.env` to the file on the host; in Helm, use `extraCaCerts` ([configuration.md](configuration.md#url-proxy-and-tls)). |

### If an agent does not connect or fails jobs

| Symptom | Cause and fix |
| --- | --- |
| The **Agents** page shows **Offline** or **Never connected**, or an old **Last seen** | The agent is not connecting. Read its log. |
| Log: `The CertPing server rejected the agent token` | The token is wrong or revoked. Create a new one. |
| Log: `CertPing has no organization yet; the agent connects once one is created` | Normal on a fresh install before the first admin exists. |
| Log: `CERTPING_AGENT_TOKEN belongs to organization ... but AGENT_ORGANIZATION_ID is ...` | Remove `AGENT_ORGANIZATION_ID` or use a token of that organization. |
| Connection errors or timeouts to the server | `CERTPING_SERVER_URL` must be the public URL (bundled agents use the internal one). Proxies must allow 60 seconds of read time on `/api/*`. Set `HTTPS_PROXY` if the network requires a proxy. |
| `429` with `too many open receive calls for this agent token` | More pollers share one token than the server allows: concurrency or replicas above `CERTPING_TRANSPORT_MAX_CONCURRENT_POLLS_PER_TOKEN`. |
| A job fails because a credential or cluster is unknown | Another agent of the same organization took the job and cannot reach that target. All agents of an organization share one queue ([agents.md](agents.md#how-agents-share-work)). |

### If a deployment fails

| Code or symptom | Fix |
| --- | --- |
| `DEPLOY_AUTH_INVALID` | The target rejected the credential. Update it under Integrations. |
| Kubernetes `Forbidden` | The identity needs `get`, `create`, `update` and `delete` on secrets in the namespace ([Kubernetes secrets](integrations.md#3-kubernetes-secrets)). |
| Kubernetes `Unauthorized` after working before | A token from `kubectl create token` expired. Use a long-lived service account token Secret. |

### If email does not arrive

| Symptom | Fix |
| --- | --- |
| No email at all | `MAIL_HOST` is empty, or the recipients are not Organization Admins with real addresses. For a localhost install the first admin's address is `admin@certping.local` unless `BOOTSTRAP_SUPER_ADMIN_EMAIL` was set at the first start. |
| `STARTTLS is required but host does not support STARTTLS` in the notifier log | `MAIL_STARTTLS` defaults to `true` and requires STARTTLS. For a relay without TLS set `MAIL_STARTTLS=false` (Helm: `notifier.mail.starttls: false`). |
| Authentication errors from the SMTP server | Check `MAIL_USERNAME` and `MAIL_PASSWORD`; for a relay without sign-in set `MAIL_SMTP_AUTH=false` (Helm: `notifier.mail.smtpAuth: false`). |
| Try email without a mail server | Compose: `docker compose --profile mailpit up -d` with `MAIL_HOST=mailpit`, `MAIL_PORT=1025`, `MAIL_SMTP_AUTH=false`, `MAIL_STARTTLS=false`; read it at http://localhost:8025. Development only. |

Failed emails are replayed every hour, up to three times
([apps/notifier/README.md](../apps/notifier/README.md#failed-deliveries)).

### If the server does not start

| Log message | Fix |
| --- | --- |
| `REDIS_PASSWORD is missing from .env` (Compose) | An `.env` from an older `setup.sh`. Run `./setup.sh --upgrade` in `deploy/compose`; it adds the missing keys. |
| `exited: server (terminated by SIGKILL)` in `docker logs`, or the container keeps restarting | The host ran out of memory and the kernel killed a Java process. Give Docker at least 4 GB of free memory, or lower the heaps on the all-in-one: `CERTPING_SERVER_HEAP` (default `1200m`), `CERTPING_AGENT_HEAP` (`512m`) and `CERTPING_NOTIFIER_HEAP` (`384m`). |
| `The LOCAL secret store needs a key: set CERTPING_LOCAL_SECRET_KEY` or `CERTPING_LOCAL_SECRET_KEY is not valid base64` | The key is missing or damaged. Restore it from your backup; a new key cannot read existing secrets. |
| Password pepper errors at startup | `PASSWORD_PEPPER_ACTIVE_VERSION` must name a `PASSWORD_PEPPER_V*` that holds a base64 32-byte key. |
| Database authentication fails | `DB_PASSWORD` no longer matches the database user. See [configuration.md](configuration.md#secrets-generated-at-install). |

## JWT signing keys

Access and refresh tokens are RS256. The server signs them with one private key and publishes
the public keys at `GET /.well-known/jwks.json`. Nothing that only verifies a token can mint one.

The kits generate a key at install. This page is for rotating it, and for anything outside
CertPing that verifies its tokens.

### Settings

| Variable | Holds | Secret? |
| --- | --- | --- |
| `JWT_ISSUER` | `iss` written into and required on every token | no |
| `JWT_AUDIENCE` | `aud`, default `certping-api` | no |
| `JWT_SIGNING_KEY_ID` | `kid` of the key that signs new tokens | no |
| `JWT_SIGNING_PRIVATE_KEY` | that key, PKCS#8 PEM (real or `\n`-escaped newlines) | **yes** |
| `JWT_PUBLISHED_KEYS` | JWKS JSON of every public key verifiers accept | no |
| `JWT_EXPIRATION`, `JWT_REFRESH_EXPIRATION` | lifetimes in milliseconds | no |

The server refuses to start if the signing key is not published, does not match its published
half, is under 2048 bits, or if the published set contains any private key material.

### Creating keys

```bash
apps/server/scripts/jwt-keygen.sh <kid> <issuer>
```

It prints the `JWT_*` lines. Keep `JWT_SIGNING_PRIVATE_KEY` in your secret store (the `.env` of
the Compose kit, the `certping` Secret in Helm, or a cloud vault) and the rest as plain
configuration. Use a `kid` that says when it was made, such as `2026-09-a`.

### Rotating without signing anyone out

A verifier must know a key before any token signed with it reaches it. `scripts/jwt-rotate.sh`
produces the values; you put them in place and restart the server after each change, because
settings are read at startup.

| # | Run or change | Effect |
| --- | --- | --- |
| 1 | `apps/server/scripts/jwt-rotate.sh add <new-kid> <dir> < current-published-keys.json` | Writes the new key pair to `<dir>`; nothing changes yet |
| 2 | `JWT_PUBLISHED_KEYS` = `<dir>/JWT_PUBLISHED_KEYS` (old and new). Signing stays on the old key | Verifiers learn the new key |
| 3 | Wait longer than the verifiers' JWKS cache (5 minutes here, plus their own refresh interval) | |
| 4 | `JWT_SIGNING_KEY_ID` and `JWT_SIGNING_PRIVATE_KEY` = the files in `<dir>`; delete `<dir>` | New tokens use the new key; old tokens still verify |
| 5 | Wait out the refresh-token lifetime (`JWT_REFRESH_EXPIRATION`) | No live token uses the old key |
| 6 | `JWT_PUBLISHED_KEYS` = output of `apps/server/scripts/jwt-rotate.sh keep <new-kid> < current-published-keys.json`; retire the old private key | Done |

If the secret store keeps versions (Azure Key Vault does), retire the old private key by disabling
its old version, not by deleting the secret: deleting a Key Vault secret deletes every version,
including the live key, and new server pods then fail to start.

If a key is compromised, skip the waits: publish only a new key and sign with it. Every session
ends at once, which is the point.

### For services that verify these tokens

Refresh tokens are signed with the same key and carry the same `iss`, `aud` and `kid`. A verifier
that checks only the signature accepts a refresh token as a login. Every verifier must:

- accept `alg` RS256 only, decided by the verifier and never by the token;
- pick the key by `kid` from the JWKS, and on an unknown `kid` refresh the JWKS at most once per
  five minutes before rejecting;
- require `iss`, `aud` (contains `certping-api`), an unexpired `exp` with at most 30 seconds of
  clock skew, and **`type` = `access`**;
- reject a revoked token: `EXISTS auth:revoked-access:<jti>` in the shared Valkey. Entries live
  until `exp` plus 60 seconds, so a longer skew would outlive the revocation.

### Checking

```bash
curl -s https://<certping-host>/.well-known/jwks.json
```

Each key must show only `kty`, `kid`, `use`, `alg`, `n` and `e`.
