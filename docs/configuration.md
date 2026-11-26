# Configuration reference

Every setting an operator can set, with its default and what it does. All settings are
environment variables. Most defaults are in the YAML of each app, listed below; some live in the
Java code (for example the sign-in lockout and some job schedules), and those are listed on this
page too:

- server: `apps/server/src/main/resources/application.yaml` and `application-selfhosted.yaml`
- agent: `apps/agent/src/main/resources/application.yml` and `application-selfhosted.yml`
- notifier: `apps/notifier/src/main/resources/application.yaml` and `application-selfhosted.yaml`
- web: `apps/web/.env.example` and `apps/web/next.config.ts`

The Java images run with `SPRING_PROFILES_ACTIVE=selfhosted` by default, as every kit does, and the
defaults below are the ones that profile gives.

How to set a variable in each kit:

| Kit | Where |
| --- | --- |
| All-in-one | `-e NAME=value` on `docker run`. The server, notifier and agent see every variable given to the container; the web app and Caddy get only `CERTPING_URL` and the site address. Recreate the container to change one. |
| Compose | `deploy/compose/.env`. The server and notifier read the whole file. The bundled agent and the web app get only the variables listed for them in `docker-compose.yml`; add others in a `docker-compose.override.yml`. |
| Helm | `values.yaml` for the values the charts expose, and the `certping` Secret for secrets. Any other variable goes in `extraEnv` (env entries) or `extraEnvFrom` (whole ConfigMaps or Secrets) of the container: `server`, `web`, `notifier` and `bundledAgent` in the `certping` chart, top-level in the `certping-agent` chart. |

## Secrets generated at install

`deploy/compose/setup.sh` (also used by the Helm chart's `create-secret.sh`) and the all-in-one
entrypoint generate these once. The all-in-one keeps them in `/var/lib/certping/config.env` on the
volume, Compose in `deploy/compose/.env`, Helm in the `certping` Secret.

| Variable | What it is | Can it change later? |
| --- | --- | --- |
| `DB_USERNAME`, `DB_PASSWORD` | PostgreSQL user and password | **No**, not by editing the file. The database user was created with this password. Change it in PostgreSQL first (`ALTER ROLE`), then in the file. |
| `PASSWORD_PEPPER_ACTIVE_VERSION`, `PASSWORD_PEPPER_V1` | AES-256 key that seals every password hash and TOTP secret | **Never** replace `V1`. Without it nobody can sign in. Rotate by adding `PASSWORD_PEPPER_V2`, making it active and running the password-hash rotation job ([self-hosting.md](self-hosting.md#protect-the-secrets-of-the-installation)). |
| `CERTPING_LOCAL_SECRET_KEY` | AES-256 key of the `LOCAL` secret store | **Never.** It decrypts every stored credential, ACME account key and private key. It cannot be rotated in place. |
| `JWT_SIGNING_KEY_ID`, `JWT_SIGNING_PRIVATE_KEY`, `JWT_PUBLISHED_KEYS`, `JWT_ISSUER`, `JWT_AUDIENCE` | RS256 key that signs access tokens | Rotate with [JWT signing keys](operations.md#jwt-signing-keys). Replacing it signs everyone out. |
| `PASSWORD_RESET_TOKEN_SECRET` | HMAC key for password-reset links | Yes. Links already sent stop working. |
| `REDIS_PASSWORD` | Valkey password | Yes, on the server and Valkey together. |
| `CERTPING_INTERNAL_TOKEN` | Token between the server and the notifier: the notifier on the agent gateway and on internal gRPC, the server on the notifier's HTTP API | Yes, on the server and notifier together. |
| `CERTPING_BOOTSTRAP_AGENT_TOKEN` | Token of the bundled agent (`cpa_...`) | Yes, on the server and bundled agent together. |
| `BOOTSTRAP_SUPER_ADMIN_USERNAME`, `_EMAIL`, `_PASSWORD`, `_DISPLAY_NAME` | First Platform Super Admin, created at the first start with a forced password change | Read only at the first start. Leave all empty to use the setup screen in the web app instead. |

Back these up separately from the database, and protect them like private keys.

## URL, proxy and TLS

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_URL` | none, required | Public URL people and remote agents use. Sets the API's CORS origin, links in email, the SSO redirect and the JWT issuer. |
| `CERTPING_SITE_ADDRESS` | from `CERTPING_URL` | Caddy's site address: `:80` for `http://localhost`, else the host name, for which Caddy gets a Let's Encrypt certificate. All-in-one and Compose. |
| `CERTPING_HTTP_PORT`, `CERTPING_HTTPS_PORT` | `80`, `443` | Host ports Caddy publishes. Compose only. |
| `CERTPING_EXTRA_CA_CERTS` | empty | A PEM file of extra CA certificates that the server, notifier and agent trust: a private ACME CA, a TLS-inspecting proxy, an internal SMTP relay or OIDC provider. All-in-one: a path inside the container (mount the file). Compose: a path on the host in `.env`; `deploy/compose/java-entrypoint.sh` mounts and adds it. Helm: `extraCaCerts.configMap` or `extraCaCerts.secret` (key `extraCaCerts.key`, default `ca.crt`) in both charts. The web app is not affected. |
| `CERTPING_CLIENT_IP_SOURCE` | `LAST_PROXY_HOP` | Which address the audit log and rate limits use. `LAST_PROXY_HOP`: the rightmost `X-Forwarded-For` entry when the request came from a private address. `FRONT_DOOR`: Azure Front Door's `X-Azure-ClientIP` when `X-Azure-FDID` matches. `PEER`: the connection's address. |
| `CERTPING_CLIENT_IP_FRONT_DOOR_ID` | empty | Your Azure Front Door ID, for `FRONT_DOOR`. |
| `CERTPING_VERSION` | Compose: `0.0.1-beta`. Server: set by the release image | Compose: the image tag; Helm uses `image.tag`. Server (property `certping.version`): the version shown as the image tag in the agent command of **Add agent**. Values that name no published image (`dev`, `latest`, a snapshot) are skipped; then the server's build version is used, else `0.0.1-beta`. |
| `CERTPING_IMAGE_PREFIX` | `ghcr.io/certping-labs` | Registry path of the images. Compose only; Helm uses `image.registry`. |

## Database (PostgreSQL)

The server runs Flyway migrations at startup. The notifier shares the database and does not
migrate it.

| Variable | Default | What it does |
| --- | --- | --- |
| `DB_URL` | `jdbc:postgresql://postgres:5432/certping` | JDBC URL, server and notifier. |
| `DB_USERNAME` | `certping` | Database user. |
| `DB_PASSWORD` | none, required | Database password. |
| `DB_POOL_SIZE` | server `40`, notifier `10` | Connections per process. `max_connections` must cover every replica's pool plus headroom. |
| `CERTPING_SERVER_DB_POOL_SIZE` | `40` | Compose: passed to the server as `DB_POOL_SIZE`. Helm: `server.dbPoolSize`. |
| `DB_LOCK_TIMEOUT` | `5s` | PostgreSQL `lock_timeout` for server sessions. |
| `DB_STATEMENT_TIMEOUT` | `30s` | PostgreSQL `statement_timeout` for server sessions. |
| `DB_IDLE_IN_TRANSACTION_TIMEOUT` | `30min` | PostgreSQL `idle_in_transaction_session_timeout` for server sessions. |

## Valkey (Redis compatible)

Valkey holds revoked access tokens, rate-limit counters and a feature flag counter. The server
fails open when it is unreachable. The settings keep their Redis names.

The kits ship different Valkey versions on purpose: the all-in-one image installs Valkey 9.0 from
Ubuntu's package archive, while Compose and Helm run the `valkey/valkey:8-alpine` image (Valkey
8.1). Both speak the same protocol to the server, and the data is short-lived, so the difference
does not matter.

| Variable | Default | What it does |
| --- | --- | --- |
| `REDIS_HOST` | `redis` | Host. |
| `REDIS_PORT` | `6379` | Port. |
| `REDIS_PASSWORD` | empty | Password. Every kit sets one and the bundled Valkey requires it. |
| `REDIS_SSL_ENABLED` | `false` | TLS to Valkey. |
| `REDIS_TIMEOUT` | `2s` | Command timeout. |
| `REDIS_HEALTH_ENABLED` | `false` | Include Valkey in the server's health status. Off because the server works without it. |

## Email (notifier)

| Variable | Default | What it does |
| --- | --- | --- |
| `MAIL_HOST` | empty | SMTP server. Empty means no email is sent. |
| `MAIL_PORT` | `587` | SMTP port. |
| `MAIL_USERNAME`, `MAIL_PASSWORD` | empty | SMTP sign-in. |
| `MAIL_SMTP_AUTH` | `true` | Sign in to the SMTP server. |
| `MAIL_STARTTLS` | `true` | Use STARTTLS and require it. Set `false` for a relay without TLS. |
| `EMAIL_FROM` | empty (`setup.sh` writes `certping@<domain>`) | Sender address. |
| `EMAIL_SUPPORT_ADDRESS` | `EMAIL_FROM` | Reply address shown in email. |
| `NOTIFICATION_CC_ALLOWED_DOMAINS` | empty | Comma-separated domains a cc address may be at; other cc addresses are dropped. |
| `CERTPING_ENVIRONMENT` | `prod` | A value other than `prod` tags email subjects, for example `staging`. |
| `NOTIFIER_REPLAY_TOKEN` | empty | Turns on `POST /api/notifications/admin/replay-undelivered` (header `X-Notifier-Replay-Token`). |
| `CERTPING_INTERNAL_URL` | `http://server:8080` | Where the notifier reaches the server. Set by the kits. |
| `CERT_MANAGER_GRPC_ADDR` | `server:50051` | The server's internal gRPC, used to check whether an organization turned a notification off. Set by the kits. |

In Helm these are `notifier.mail.host`, `.port`, `.username`, `.from`, `.starttls` and
`.smtpAuth`; the password is `MAIL_PASSWORD` in the `certping` Secret.

## Single sign-on

One OpenID Connect provider for the whole installation. Sign-in stays local only until the
issuer, client id, client secret and organization are all set. Guide:
[self-hosting.md](self-hosting.md#single-sign-on-openid-connect).

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_OIDC_ISSUER_URI` | empty | The provider's issuer URL. |
| `CERTPING_OIDC_CLIENT_ID` | empty | Client id. |
| `CERTPING_OIDC_CLIENT_SECRET` | empty | Client secret. |
| `CERTPING_OIDC_ORGANIZATION` | empty | Slug or id of the organization people are signed into. |
| `CERTPING_OIDC_DISPLAY_NAME` | `Single sign-on` | Button label on the login page. |
| `CERTPING_OIDC_SCOPES` | `openid profile email` | Requested scopes. |
| `CERTPING_OIDC_DEFAULT_ROLE` | `VIEWER` | Built-in role for people provisioned at first sign-in. `SUPER_ADMIN` is refused. |
| `CERTPING_OIDC_AUTO_PROVISION` | `true` | `false` lets only invited members (matched by email) use the provider. |

SAML, SCIM and group-to-role mapping are not available in CertPing and have no settings.

## Sign-in, security and rate limits

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_RATE_LIMIT_AUTH_ENABLED` | `true` | Per-address limit on sign-in, MFA, forgot-password, reset-password and the SSO code exchange. |
| `CERTPING_RATE_LIMIT_AUTH_MAX_REQUESTS` | `20` | Requests per endpoint per address per window. Over it: `429` with `Retry-After`. |
| `CERTPING_RATE_LIMIT_AUTH_WINDOW` | `PT5M` | The window. |
| `APP_AUTH_LOCKOUT_MAX_FAILED_ATTEMPTS` | `5` | Failed sign-ins before an account is locked. |
| `APP_AUTH_LOCKOUT_DURATION` | `PT15M` | How long the lock lasts. |
| `JWT_EXPIRATION` | `3600000` (1 hour) | Access token lifetime, milliseconds. |
| `JWT_REFRESH_EXPIRATION` | `604800000` (7 days) | Refresh token lifetime, milliseconds. |
| `INTEGRATIONS_ALLOW_PRIVATE_ADDRESSES` | `false` | Allow Slack, Teams, webhook and ServiceNow URLs that resolve to private, loopback or link-local addresses. |
| `SWAGGER_ENABLED` | `false` | Serve the OpenAPI document and Swagger UI. |
| `CERTPING_ORGANIZATION_NAME` | `My organization` | Name of the organization created for the first admin. |
| `CERTPING_ORGANIZATION_DOMAIN` | host of `CERTPING_URL` | Its domain. |

## Agent gateway and queue (server)

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_INTERNAL_TOKEN` | generated | Token between the server and the notifier. Required on the notifier's HTTP API (except `/actuator/health`) and on internal gRPC; with it unset, both refuse every call. |
| `CERTPING_BOOTSTRAP_AGENT_TOKEN` | generated | Token the bundled agent starts with. |
| `CERTPING_BOOTSTRAP_AGENT_ORG` | empty | Slug of the organization the bundled agent works for; empty means the first one. |
| `CERTPING_TRANSPORT_MAX_CONCURRENT_POLLS_PER_TOKEN` | `8` | Open long polls per agent token on one server. |
| `CERTPING_TRANSPORT_MAX_REQUESTS_PER_TOKEN_PER_MINUTE` | `1200` | Poll calls per token per minute. Over it: `429` with `Retry-After`. |
| `CERTPING_TRANSPORT_MAX_SETTLE_REQUESTS_PER_TOKEN_PER_MINUTE` | `6000` | Complete, abandon, renew-lock and send calls per token per minute. |
| `CERTPING_TRANSPORT_POLL_CHECK_MIN`, `CERTPING_TRANSPORT_POLL_CHECK_MAX` | `250ms`, `2s` | Pause between queue checks inside one long poll, growing while the queue is empty. |
| `CERTPING_TRANSPORT_MAX_WAITING_MESSAGES_PER_ORGANIZATION` | `10000` | Messages one organization may have waiting. |
| `CERTPING_TRANSPORT_MAX_REQUEST_BODY_BYTES` | `8388608` (8 MiB) | Largest gateway request body; `413` over it. |
| `CERTPING_TRANSPORT_DISCOVERY_COMMAND_TTL` | `1h` | A discovery job no agent picks up in this time expires. |
| `CERTPING_TRANSPORT_INBOUND_QUEUE_PATTERN`, `CERTPING_TRANSPORT_OUTBOUND_QUEUE` | `{orgId}-agent-inbound`, `cert-agent-outbound` | Queue names. Do not change them on a running install: queued messages keep the old name. |
| `INTERNAL_GRPC_ENABLED`, `INTERNAL_GRPC_PORT` | `true`, `50051` | Internal gRPC for the notifier. Every call needs `CERTPING_INTERNAL_TOKEN` as `authorization: Bearer` metadata; never expose it. |
| `INTERNAL_GRPC_BIND_ADDRESS` (`certping.internal-grpc.bind-address`) | `127.0.0.1` | Address the internal gRPC port opens on. The all-in-one keeps the default, Helm sets the pod IP, and Compose uses `server-grpc`, the server's alias on the internal `notifier` network. `0.0.0.0` opens it on every interface; avoid it. |
| `NOTIFICATION_SERVICE_BASE_URL`, `STATUS_AGENT_BASE_URL` | set by the kits | Where the server reaches the notifier and the bundled agent's health endpoint. |
| `CERTPING_VIRTUAL_THREADS` | `true` | Java virtual threads, in all three Java services. |

## Agent

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_SERVER_URL` | none, required | The CertPing URL the agent connects to. Bundled agents use the internal address. |
| `CERTPING_AGENT_TOKEN` | none, required | The agent token. |
| `AGENT_ORGANIZATION_ID` | empty | Optional check: the agent refuses to start if the token belongs to another organization. |
| `CERTPING_AGENT_BUNDLED` | `false` | Marks the agent that runs beside the server. The kits set it to `true` on their bundled agent (all-in-one, Compose, the `certping` chart). It only changes how the **Agents** page labels the agent (**Bundled**); leave it unset on remote agents. |
| `CERTPING_AGENT_MAX_CONCURRENT_JOBS` | `8` | Jobs handled at the same time, one gateway poller each. |
| `CERTPING_AGENT_MAX_LOCK_RENEWAL` | `30m` | How long the agent keeps renewing its hold on one job. |
| `AGENT_SECRET_STORE_PROVIDER` | `LOCAL` | `LOCAL`, `AZURE_KV`, `AWS_SECRETS_MANAGER` or `GCP_SECRET_MANAGER`. |
| `CERTPING_LOCAL_SECRET_DIR` | `/var/lib/certping/secrets` | Directory of the `LOCAL` store. |
| `CERTPING_LOCAL_SECRET_KEY` | empty | Key of the `LOCAL` store; the same value as the server's. |
| `CLIENT_KV_URI`, `AZURE_KV_AUTH_MODE` | empty, `DEFAULT` | Azure Key Vault URI and auth mode (`WORKLOAD_IDENTITY`, `CLIENT_SECRET`, `CLIENT_CERTIFICATE`, `DEFAULT`). |
| `AWS_REGION`, `AWS_SM_AUTH_MODE` | empty, `DEFAULT` | AWS Secrets Manager region and auth mode (`WEB_IDENTITY_TOKEN`, `INSTANCE_PROFILE`, `PROFILE`, `STATIC`, `DEFAULT`). |
| `GCP_PROJECT_ID`, `GCP_SM_AUTH_MODE` | empty, `ADC` | Google Secret Manager project and auth mode (`ADC`, `WORKLOAD_IDENTITY_FEDERATION`, `SA_JSON`). |
| `ACME_DIRECTORY_URL` | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory. Let's Encrypt staging is `https://acme-staging-v02.api.letsencrypt.org/directory`. See the warning under [ACME](#acme). |
| `ACME_ACCOUNT_EMAIL` | empty | Contact on the ACME account the agent registers per organization. |
| `ACME_EAB_KEY_ID`, `ACME_EAB_HMAC_KEY` | empty | External account binding, for a CA that requires it (ZeroSSL, Google Trust Services, SSL.com and others): the key id and HMAC key the CA issues. Used when the agent registers an account; set both or neither, and keep the HMAC key secret. |
| `NAMECHEAP_CLIENT_IP` | empty | Public IP allowlisted at Namecheap. Required for Namecheap DNS. |
| `CERTPING_DNS_API_URL` | `https://dns-api.certping.com/api/v1/domains/token-api` | Base URL of the CertPing DNS API. The lab points it at a local stand-in. |
| `HTTPS_PROXY` | empty | Proxy for the agent's connection to the CertPing server. Calls to CAs, DNS and cloud APIs do not read it; for those, JVM proxy properties in `JAVA_OPTS` may apply depending on the client library. |
| `AGENT_SCHEDULER_POOL_SIZE` | `4` | Threads for the agent's own scheduled tasks (heartbeat, health reports). |
| `SCEP_ENABLED` and `SCEP_*` | `false` | SCEP endpoint for machine identity (experimental). See [Machine identity](integrations.md#machine-identity-experimental). |
| `DIGICERT_API_BASE_URL` | `https://www.digicert.com/services/v2` | DigiCert CertCentral API. The API key itself is entered per organization in CertPing. |
| `AGENT_GLOBALSIGN_API_KEY`, `AGENT_GLOBALSIGN_API_SECRET` | empty | GlobalSign Atlas API key and secret. |
| `AGENT_GLOBALSIGN_CLIENT_CERT_PEM_BASE64`, `AGENT_GLOBALSIGN_CLIENT_PRIVATE_KEY_PEM_BASE64` | empty | The Atlas mTLS client certificate and key, base64 of the PEM. Without these settings GlobalSign orders fail with `GLOBALSIGN_CONFIG_MISSING`. |
| `AGENT_GLOBALSIGN_API_BASE_URL` | `https://emea.api.hvca.globalsign.com:8443/v2` | GlobalSign Atlas API. The `AGENT_GLOBALSIGN_*_JSON` policy settings are in `application-selfhosted.yml`. |

GlobalSign issues on one account configured on the agent, not per organization. Set it on every
agent that should issue from it.

Other `agent.*` properties in `application.yml` (for example the ACME timing under
`agent.acme.*` and the retry policy under `agent.retry.*`) can be set with Spring's environment
variable form: dots and dashes become underscores, all upper case.

The Helm charts map their values to these variables: `acme.directoryUrl` and `acme.accountEmail`
in the `certping-agent` chart ([README](../deploy/charts/certping-agent/README.md)),
`bundledAgent.acme.directoryUrl` and `bundledAgent.acme.accountEmail` for the bundled agent of the
`certping` chart (which `bundledAgent.enabled: false` turns off). Other agent variables go in
`extraEnv` or `extraEnvFrom`.

## Jobs and schedules (server)

Cron expressions have six fields (the first is seconds) and run in UTC. The jobs listed in
`application.yaml` also have an `_ENABLED` variable, default `true`, for example
`CERTPING_JOBS_TRIGGER_RENEWALS_ENABLED`.

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_JOBS_MARK_EXPIRED_CERTS_CRON` | `0 0 2 * * *` | Marks expired certificates. |
| `CERTPING_JOBS_TRIGGER_RENEWALS_CRON` | `0 0 3 * * *` | Queues a renewal for every eligible certificate. |
| `CERTPING_JOBS_RETRY_RENEWALS_CRON` | `0 */5 * * * *` | Retries renewals that failed and are due for another attempt. |
| `CERTPING_JOBS_RECOVER_STALLED_RENEWALS_CRON` | `0 40 * * * *` | Recovers renewals that stopped making progress. |
| `CERTPING_JOBS_TRIGGER_EXPIRY_ALERTS_CRON` | `0 0 8 * * *` | Sends expiry alerts. |
| `CERTPING_JOBS_TRIGGER_EXPIRY_ALERTS_THRESHOLDS_DAYS` | `30,14,7,3,1` | One alert as a certificate crosses each threshold. |
| `CERTPING_JOBS_TRIGGER_EXPIRY_ALERTS_DAYS_BEFORE_EXPIRY` | `30` | Look-ahead of the alert job. |
| `CERTPING_JOBS_SOFT_DELETE_PURGE_CRON` | `0 0 3 * * *` | Purges soft-deleted records. |
| `CERTPING_JOBS_EXPIRY_CLEANUP_CRON` | `0 0 4 * * *` | Soft-deletes `EXPIRED` and `REVOKED` certificates older than 24 hours. |
| `CERTPING_JOBS_QUEUE_ALERT_CRON` | `0 */5 * * * *` | Checks queue and dead-letter depth ([operations.md](operations.md#watch-the-queue-and-the-agents)). |
| `CERTPING_JOBS_AUDIT_PARTITIONS_CRON` | `0 17 */6 * * *` | Keeps audit table partitions three months ahead. |
| `CERTPING_JOBS_AUDIT_RETENTION_CRON` | `0 30 4 * * *` | Drops audit months older than the retention a Platform Super Admin confirmed. Nothing is dropped until then. |
| `CERTPING_JOBS_DRAIN_BUDGET_MAX_ROWS_PER_RUN`, `CERTPING_JOBS_DRAIN_BUDGET_MAX_RUN_DURATION` | `10000`, `30m` | Most rows and longest time one job run handles; the rest continues on the next five-minute tick. |
| `CERTPING_JOBS_TRIGGER_IOT_*` | see `application.yaml` | Machine identity jobs (experimental). |

The renewal window is 30 days, capped at a third of the certificate's lifetime
([Renewal](architecture.md#renewal)). Queue-depth alert thresholds are
`CERTPING_ALERTS_QUEUE_DEPTH_DEFAULT_ACTIVE_THRESHOLD` (`1000`),
`CERTPING_ALERTS_QUEUE_DEPTH_DEFAULT_DLQ_THRESHOLD` (`1`) and
`CERTPING_ALERTS_QUEUE_DEPTH_COOLDOWN_MINUTES` (`60`).

## Audit log

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_AUDIT_CUSTOMER_VISIBLE_DAYS` | `90` | How far back organization members can see their trail. Rows are kept longer, per the retention setting. |
| `CERTPING_AUDIT_EXPORT_MAX_ROWS` | `10000` | Largest export; a larger one is refused with `EXPORT_TOO_LARGE`. |
| `CERTPING_AUDIT_EXPORTS_PER_HOUR` | `10` | Exports per organization per hour. |
| `CERTPING_AUDIT_COUNT_CAP` | `10000` | The list counts matching rows up to this number. |

The remaining `CERTPING_AUDIT_*` timeouts and the asynchronous writer settings are in
`application.yaml`.

## Telemetry and tracing

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_TELEMETRY_ENABLED` | `false` | Opt-in daily usage report to Seaionl Inc. Every field is listed in [Privacy and telemetry](self-hosting.md#privacy-and-telemetry). |
| `CERTPING_TELEMETRY_ENDPOINT` | `https://telemetry.certping.com/v1/report` | Where it goes. |
| `CERTPING_TELEMETRY_INTERVAL`, `CERTPING_TELEMETRY_INITIAL_DELAY` | `PT24H`, `PT60M` | How often, and the delay after start. |
| `OTEL_JAVAAGENT_ENABLED` | `false` | The OpenTelemetry Java agent in the server, agent and notifier images. Off by default in the images and every kit; the all-in-one image does not load it at all. Set `true` together with `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | empty | Your OTLP collector. Compose passes it to the Java services. |
| `OTEL_SDK_DISABLED`, `OTEL_EXPORTER_OTLP_*` | unset | OpenTelemetry for the web app's Node.js server. It starts only when an OTLP variable is set. The kits do not pass these to the web container. |

## Logging

The Java services log to standard output, one line per event. Server and agent lines carry
`[req=... corr=... msg=... org=...]`, notifier lines the correlation and organization ids, so one
request can be followed across services. The
`selfhosted` profile logs at `WARN`, and at `INFO` for CertPing's own packages. Change levels
with Spring's variables, for example:

```sh
LOGGING_LEVEL_ROOT=INFO
LOGGING_LEVEL_COM_CERTMANAGEMENT=DEBUG   # server
LOGGING_LEVEL_COM_CERTPING=DEBUG         # agent and notifier
```

## Secret store (server)

The server writes pasted credentials into the agent secret store; it needs the same store
settings as the agents that read them. The secrets of the Slack, Teams, PagerDuty and ServiceNow
integrations are kept in the same store; only the server reads those.

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_AGENT_SECRET_STORE_PROVIDER` | `LOCAL` | `LOCAL`, `AZURE_KV`, `AWS_SECRETS_MANAGER` or `GCP_SECRET_MANAGER`. |
| `CERTPING_LOCAL_SECRET_DIR` | `/var/lib/certping/secrets` | Directory shared with the bundled agent. |
| `CERTPING_LOCAL_SECRET_KEY` | generated | Base64 of 32 random bytes. Same value on the server and the bundled agent. |

The cloud stores' properties are under `certping.agent-secret-store.*`
(`AgentSecretStoreProperties` in the server). The kits only configure `LOCAL`.

## ACME

| Variable | Default | What it does |
| --- | --- | --- |
| `ACME_DIRECTORY_URL` | Let's Encrypt production | Any ACME CA works: Let's Encrypt staging, step-ca, Pebble, and with external account binding ZeroSSL, Google Trust Services and SSL.com. For a CA with a private root, also trust it (`CERTPING_EXTRA_CA_CERTS`). |
| `ACME_ACCOUNT_EMAIL` | empty | ACME account contact. |
| `ACME_EAB_KEY_ID`, `ACME_EAB_HMAC_KEY` | empty | External account binding: the key id and HMAC key from the CA, used when the agent registers an account. The agent registers one account per organization; some CAs accept each key for one account only, so check your CA before you add a second organization. |

The agent keeps one ACME account per organization and directory, stored in its secret store as
`acme-acct-<organization id>-<hash of the directory URL>`. To switch, for example from Let's
Encrypt staging to production, change `ACME_DIRECTORY_URL` and restart; the agent registers a new
account for the new directory at the next order.

DNS-01 timing, all agent properties: the first propagation check waits
`agent.acme.challenge.dns-propagation-wait-ms` (30 seconds), then the agent checks every
nameserver of the zone every 5 seconds, up to 60 times (`agent.acme.automated-dns-verification.*`),
before it retries the whole attempt later.

## Web app

| Variable | Default | When | What it does |
| --- | --- | --- | --- |
| `CERTPING_URL` | `http://localhost` | Runtime | Public URL. With `same-origin`, the web app's Node.js server uses it to render API links, so they match what the browser uses. Every kit sets it; change it and restart, no rebuild. |
| `NEXT_PUBLIC_API_URL` | `same-origin` (Dockerfile default) | Build | Where the browser calls the API. `same-origin` means the page's own origin, with `/api` routed to the server by Caddy or the Ingress, as every kit does. Released images use it, so one image serves any domain and no build argument is needed. A custom build can set an absolute `http(s)` URL, or a path such as `/api-proxy`. |
| `NEXT_PUBLIC_APP_MODE` | images: `enterprise` | Build | Which sign-in pages are built. |
| `NEXT_DEPLOYMENT_ID` | empty | Build | Build identifier for Next.js version-skew handling, usually the release version. Dots become hyphens (`0.0.1-beta` becomes `0-1-0`). |
| `CERTPING_API_TARGET` | unset | Development only | Origin that `/api-proxy/*` forwards to, with `NEXT_PUBLIC_API_URL=/api-proxy` (`pnpm dev`). It is read when `next build` runs, so setting it on a released image's container does nothing. |
| `NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP` | empty | Build | The IP shown in the Namecheap form as the address to allowlist. |

`NEXT_PUBLIC_*` values are baked in at build time and cannot change at runtime. Browser log
records go to the web app's own route `/web-api/logger`, which stays outside `/api`, so the proxy
sends it to the web app and not to the server.

## Resources (all-in-one)

| Variable | Default | What it does |
| --- | --- | --- |
| `CERTPING_SERVER_HEAP`, `CERTPING_AGENT_HEAP`, `CERTPING_NOTIFIER_HEAP` | `1200m`, `512m`, `384m` | JVM heap sizes. |
