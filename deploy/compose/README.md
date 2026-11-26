# CertPing with Docker Compose

The Compose kit runs each CertPing service in its own container on one machine. Use it on a laptop
to try CertPing, or on a single server you will keep.

## What runs

| Service | What it does |
| --- | --- |
| `proxy` | Caddy. The only public port. Gets and renews a TLS certificate for your domain. |
| `web` | The CertPing web app. |
| `server` | The control plane API, the agent gateway and the work queue. |
| `notifier` | Sends email. (Slack, Teams, PagerDuty and ServiceNow are called by the server.) |
| `agent` | The bundled agent: talks to CAs, DNS providers and deployment targets. |
| `postgres` | All state, including the message queue. Back this up. |
| `redis` | Valkey 8.1 (Redis compatible, BSD-3-Clause): revoked tokens, rate limits and a flag cache. Requires `REDIS_PASSWORD`. Data in the `valkey-data` volume. |

There is no message broker and nothing in Azure, AWS or GCP is required. The server keeps its work
queue in PostgreSQL, and every agent, including the bundled one, connects to the server over
outbound HTTPS with its own token.

The services are split into four networks, so each container reaches only the peers it needs:

| Network | Internal | Members | Purpose |
| --- | --- | --- | --- |
| `edge` | No | `proxy`, `web`, `server`, `agent` | The published ports, and internet access for the server and the agent |
| `notifier` | Yes | `server`, `notifier` | The notifier's HTTP API and the server's internal gRPC port, which opens only on the alias `server-grpc` on this network |
| `data` | Yes | `postgres`, `redis`, `server`, `notifier` | PostgreSQL and Valkey |
| `mail` | No | `notifier`, `mailpit` | The way out to your SMTP server |

Web, the proxy and the agent cannot reach the notifier, port 50051, PostgreSQL or Valkey. On top
of the network split, the notifier's HTTP API (except `/actuator/health`) and the internal gRPC
port require `CERTPING_INTERNAL_TOKEN`, which `setup.sh` generates in `.env`. Details are in
[docs/architecture.md](../../docs/architecture.md#compose-networks).

The server and the bundled agent share the `agent-secrets` volume and `CERTPING_LOCAL_SECRET_KEY`,
so the server can read the private keys the bundled agent holds. See
[docs/architecture.md#key-custody-and-trust](../../docs/architecture.md#key-custody-and-trust) for the layout that avoids this.

## Quickstart on a laptop

Needs Docker with Compose v2 and `openssl`.

```bash
cd deploy/compose
./setup.sh
docker compose up -d
```

This pulls the released images. `CERTPING_VERSION` defaults to `0.0.1-beta`; set it in `.env` to
pin another release.

Open http://localhost and sign in as `admin`. `setup.sh` generated a random first password and
does not print it; read it from `.env`, which only you can open:

```bash
grep '^BOOTSTRAP_SUPER_ADMIN_PASSWORD=' .env
```

You choose a new password at the first sign-in. If you would rather create the first Platform
Super Admin on the setup screen, empty the `BOOTSTRAP_SUPER_ADMIN_*` lines before the first start.
The bundled agent connects on its own to the first organization; to choose another, set
`CERTPING_BOOTSTRAP_AGENT_ORG` in `.env` to that organization's slug.

## Build from source

For local development, build the images from this checkout under the tag `dev`, so they never
mix with a release:

```bash
CERTPING_VERSION=dev docker compose build
CERTPING_VERSION=dev docker compose up -d
```

The first build takes several minutes.

## A real server

1. Point a DNS name at the server and open ports 80 and 443.
2. Run `./setup.sh certping.example.com`. Caddy obtains the certificate from Let's Encrypt.
3. Fill in the `MAIL_*` settings in `.env` so notifications can be sent.
4. `docker compose up -d`

Sizing: 2 vCPU and 4 GB of memory is enough for a few thousand certificates.

## Agents in other networks

The bundled agent can reach what the server can reach. For targets in another network (a data
center, a VPC, a customer site), run another agent there:

1. In CertPing, open **Agents** and select **Add agent**. Choose where the agent keeps keys and
   select **Create token**. Copy the token; it is shown once.
2. On a machine in that network (this example uses Azure Key Vault with the host's managed
   identity):

```bash
docker run -d --name certping-agent --restart unless-stopped \
  -e SPRING_PROFILES_ACTIVE=selfhosted \
  -e CERTPING_SERVER_URL=https://certping.example.com \
  -e CERTPING_AGENT_TOKEN=cpa_... \
  -e AGENT_SECRET_STORE_PROVIDER=AZURE_KV -e CLIENT_KV_URI=https://<vault>.vault.azure.net \
  -e AZURE_KV_AUTH_MODE=DEFAULT \
  ghcr.io/certping-labs/certping-agent:0.0.1-beta
```

It shows **Online** on the **Agents** page within a few seconds.

Use the same version as the server.

More on remote agents, workload identity and how agents share work: [docs/agents.md](../../docs/agents.md).

The agent needs only outbound HTTPS to the CertPing server, and `HTTPS_PROXY` is honoured for that
connection. Private keys stay in that network's secret manager (`AZURE_KV`, `AWS_SECRETS_MANAGER` or
`GCP_SECRET_MANAGER`). The `LOCAL` store is only for the bundled agent, which shares a volume with
the server.

## Operations

Back up the `postgres-data` and `agent-secrets` volumes and the `.env` file. The keys in `.env`
decrypt the secrets volume and the password hashes. Without them a backup cannot be restored, and
with them it holds every secret, so store it encrypted. The backup and restore commands are in
[docs/operations.md](../../docs/operations.md#back-up-and-restore-the-compose-kit).

To upgrade, run `./setup.sh --upgrade` first. It adds the keys a newer release needs to an
existing `.env` (for example `REDIS_PASSWORD`, without which Compose stops with an error) and
never changes or removes a key that is already there. Then set `CERTPING_VERSION` in `.env` to
the new release and run `docker compose pull && docker compose up -d`. The server runs the
database migrations when it starts.

If you upgrade from a kit that ran Redis, note that the store is now Valkey 8.1 (Redis compatible,
BSD-3-Clause), with the same setting names (`REDIS_HOST`, `REDIS_PASSWORD`). Valkey cannot read
the data files of Redis 7.4 or 8, so it uses a new `valkey-data` volume and starts empty. That is
safe, because it holds only revoked tokens, rate limits and a flag cache. Remove the old volume
with `docker volume rm certping_redis-data`.

To check that an installation works, run `./smoke-test.sh`. It signs in, creates an organization
if none exists, sends the bundled agent a command, waits for its answer and checks agent tokens.

To try email without an SMTP server, set `MAIL_HOST='mailpit'`, `MAIL_PORT='1025'`,
`MAIL_SMTP_AUTH='false'` and `MAIL_STARTTLS='false'` in `.env`, run
`docker compose --profile mailpit up -d`, and read the mail at http://localhost:8025. Mailpit
keeps mail in plain text with no authentication, so use it on a laptop only.

The logs are in `docker compose logs -f server agent`. To revoke an agent, open it on the
**Agents** page and select **Revoke token**; a revoked token stops working at the next request.

## Common settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTPING_VERSION` | `0.0.1-beta` | Release tag of the images. Change it to upgrade. |
| `CERTPING_URL` | from setup.sh | Public URL that people and remote agents use. |
| `CERTPING_HTTP_PORT`, `CERTPING_HTTPS_PORT` | `80`, `443` | Host ports Caddy publishes. On a laptop where 80 is taken, set `CERTPING_HTTP_PORT='8088'` and `CERTPING_URL='http://localhost:8088'`. |
| `CERTPING_BOOTSTRAP_AGENT_ORG` | empty | Organization slug the bundled agent belongs to; empty means the first one. |
| `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `EMAIL_FROM` | empty | SMTP for notifications. |
| `MAIL_STARTTLS`, `MAIL_SMTP_AUTH` | `true` | Set both to `false` for a relay without TLS or sign-in. |
| `ACME_DIRECTORY_URL`, `ACME_ACCOUNT_EMAIL` | Let's Encrypt production, empty | The bundled agent's ACME CA and account contact. |
| `ACME_EAB_KEY_ID`, `ACME_EAB_HMAC_KEY` | empty | External account binding, for a CA that requires it (ZeroSSL, Google Trust Services, SSL.com). |
| `CERTPING_EXTRA_CA_CERTS` | empty | Path on this machine to a PEM file of extra CA certificates (a private ACME CA, a TLS-inspecting proxy, an internal SMTP relay). `java-entrypoint.sh` adds them to the trust store of the server, notifier and agent. |
| `OTEL_JAVAAGENT_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT` | off | Send traces and metrics to your collector. |
