# CertPing all-in-one image

One container with the whole product: the server, the web app, the notifier, an agent, Caddy,
and its own PostgreSQL 18 and Valkey (Redis compatible). Use it to try CertPing, or to run it for
a homelab or a small team. It is built from the same application images as the Compose kit and
the Helm chart, so the application code is identical and only the packaging differs.

It does not scale out. Everything runs in one process tree on one host with one volume. For high availability, remote agents in several networks, or an existing PostgreSQL, use
the [Compose kit](../compose/README.md) or the Helm chart (`deploy/charts/certping`, see [docs/self-hosting.md](../../docs/self-hosting.md)).

## Run

```sh
docker run -d --name certping \
  -p 80:80 -p 443:443 \
  -v certping:/var/lib/certping \
  -e CERTPING_URL=http://localhost \
  ghcr.io/certping-labs/certping:0.0.1-beta
docker exec certping certping-admin
```

The first administrator is created for you with a random password. The log shows only the
username (`admin`); the password is never written to the log. Read it with
`docker exec certping certping-admin`, which prints the URL, the username and the initial
password from the volume's `config.env`. You are asked to choose a new password at the first
sign-in, and you land in "My organization" with every page available (`CERTPING_ORGANIZATION_NAME` names it). For a server
with a DNS name, set `CERTPING_URL=https://certping.example.com` and open ports 80 and 443; Caddy
obtains the TLS certificate from Let's Encrypt. The first start takes two to four minutes
(database initialization and three JVMs); `docker logs -f certping` shows it.

Needs about 4 GB of memory and two CPUs; an ARM64 host (Apple Silicon, Raspberry Pi 5) works.
The bundled agent connects to that organization on its own.

## Settings

Everything is an environment variable on the container. The server, the notifier and the agent
see these; the web app and Caddy start from an empty environment and get only what they need:

| Variable | Meaning |
|---|---|
| `CERTPING_URL` | The public URL. Changeable between restarts. |
| `CERTPING_OIDC_*` | Single sign-on with your OpenID Connect provider ([docs/self-hosting.md](../../docs/self-hosting.md#single-sign-on-openid-connect)). |
| `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `EMAIL_FROM` | Outgoing email. |
| `MAIL_STARTTLS`, `MAIL_SMTP_AUTH` | Both `true` by default. Set to `false` for an internal relay without TLS or sign-in. |
| `ACME_DIRECTORY_URL`, `ACME_ACCOUNT_EMAIL` | The ACME CA the bundled agent uses (Let's Encrypt by default). |
| `ACME_EAB_KEY_ID`, `ACME_EAB_HMAC_KEY` | External account binding, for a CA that requires it (ZeroSSL, Google Trust Services, SSL.com). |
| `CERTPING_EXTRA_CA_CERTS` | Path (inside the container) to a PEM file of extra CA certificates to trust, for a private ACME CA or a TLS-inspecting proxy. Mount the file read-only. |
| `BOOTSTRAP_SUPER_ADMIN_USERNAME`, `_EMAIL`, `_PASSWORD` | Your own first admin instead of the generated one (set before the first start). |
| `CERTPING_TELEMETRY_ENABLED` | Opt-in usage report ([docs/self-hosting.md#privacy-and-telemetry](../../docs/self-hosting.md#privacy-and-telemetry)); off by default. |
| `CERTPING_SERVER_HEAP`, `CERTPING_AGENT_HEAP`, `CERTPING_NOTIFIER_HEAP` | JVM heap sizes (1200m, 512m, 384m). |

## What is on the volume

`/var/lib/certping` holds `postgres/` (the database), `secrets/` (the agent's encrypted private
keys and credentials), `caddy/` (TLS certificates for the site), `valkey/`, and `config.env`: the
database password, the password pepper, the JWT signing key, the local secret key, the agent
token, the Valkey password (`REDIS_PASSWORD`) and the first administrator's initial password,
all generated on the first start. `config.env` is readable by root only; at each start the entrypoint copies to
`/run/certping/<service>.env` just the values each service needs (0600, owned by that service's
account: `certping` for the server and agent, `certping-notifier`, `certping-web`,
`certping-caddy`), so the web app and Caddy hold no secrets. The database cannot be used without
`config.env`, and the reverse, so back them up together. The simplest complete backup is the whole volume, taken while the
container is stopped. The archive holds every secret in `config.env`, so store it encrypted:

```sh
umask 077
docker stop certping
docker run --rm -v certping:/data busybox tar czf - -C /data . > certping.tgz
docker start certping
```

The restore, and an online backup with `pg_dump`, are in
[docs/operations.md](../../docs/operations.md#back-up-the-all-in-one).

## Upgrade

```sh
docker pull ghcr.io/certping-labs/certping:<new version>
docker stop certping && docker rm certping
docker run ... (the same command with the new tag)
```

The server migrates the database at startup. Back up the volume first; the backup with the old
image is the rollback.

If you upgrade from an image that ran Redis: the image now runs Valkey 9.0.4 (Redis compatible, BSD-3-Clause)
from Ubuntu's archive. Valkey cannot read the files Redis 8 wrote, so on the first start the
entrypoint moves them to `/var/lib/certping/redis.pre-valkey` and Valkey starts empty. That is
safe: the store holds only revoked tokens, rate-limit counters and a feature flag cache. Delete
the old folder when you like:

```sh
docker exec certping rm -rf /var/lib/certping/redis.pre-valkey
```

## Build it yourself

For a local development build, from the repository root:

```sh
make images
```

It builds the four application images under the tag `dev` and then the all-in-one as
`certping-allinone:dev`, the image the end-to-end lab uses. It runs these two steps:

```sh
CERTPING_VERSION=dev docker compose -f deploy/compose/docker-compose.yml build
docker build -f deploy/all-in-one/Dockerfile --build-arg CERTPING_VERSION=dev -t certping-allinone:dev .
```

To build the all-in-one from published release images instead, skip the first step and pass the
release: `--build-arg CERTPING_VERSION=<version>`.

`CERTPING_VERSION` picks the release tag of the four application images (it never defaults to
`latest`). `--build-arg SERVER_IMAGE=...` (and `WEB_IMAGE`, `AGENT_IMAGE`, `NOTIFIER_IMAGE`) point
it at other application images, for example a release's digests or images you built locally.
