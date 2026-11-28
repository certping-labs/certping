# Self-hosting CertPing

CertPing runs on any host with Docker, or on Kubernetes. Pick the install that matches what you
already have:

| You have | Use | Guide |
| --- | --- | --- |
| A laptop, a homelab or a trial | One container with its own database (`docker run`) | [deploy/all-in-one](../deploy/all-in-one/README.md) |
| One Linux server you will keep | Docker Compose (separate PostgreSQL, Valkey and services) | [deploy/compose](../deploy/compose/README.md) |
| An Azure subscription, no cluster | Terraform: one VM running Compose | [deploy/azure/single-vm](../deploy/azure/single-vm/README.md) |
| A Kubernetes cluster | Helm | [deploy/charts/certping](../deploy/charts/certping/README.md) |
| Targets in other networks | An extra agent per network | [agents.md](agents.md) and [deploy/charts/certping-agent](../deploy/charts/certping-agent/README.md) |

New to CertPing? [getting-started.md](getting-started.md) walks through a first certificate on the
all-in-one image. [Release assets](release-assets.md) explains which download to use.
Every setting is in [configuration.md](configuration.md). Upgrades, backups and troubleshooting
are in [operations.md](operations.md).

Valkey (Redis compatible, BSD-3-Clause) is the store the server uses for revoked tokens, rate
limits and a flag cache. The settings keep their Redis names (`REDIS_HOST`, `REDIS_PASSWORD`), and
a password is required. An install that ran Redis starts Valkey empty, which is safe for this
data; the Compose and all-in-one READMEs say how to remove the old Redis files.

## How the pieces connect

A proxy (Caddy in the kits, your Ingress in Helm) sends `/api/*` to the server and everything else
to the web app. The server keeps state and its work queue in PostgreSQL. The notifier and every
agent connect to the server over HTTPS. The diagram is in [architecture.md](architecture.md).

- There is no message broker. The server keeps its work queue in PostgreSQL (the `message_queue`
  table). Agents and the notifier long-poll the server's agent gateway (`/api/v1/agent-gateway`)
  over HTTPS. Each poll asks to wait 20 seconds for work; the server caps any poll at 25 seconds.
- Agents only dial out. An agent needs outbound HTTPS to the CertPing URL, nothing inbound, so it
  works behind NAT and firewalls. `HTTPS_PROXY` is honoured for its connection to the server; see
  [agents.md](agents.md#networking) for the other hosts it calls.
- Each agent has its own token. Open **Agents** and use **Add agent**
  ([agents.md](agents.md#create-an-agent-token)). The token decides which organization the
  agent works for; revoking it disconnects the agent at its next request. All agents of one
  organization share its job queue ([agents.md](agents.md#how-agents-share-work)), so a token is
  trusted for the whole organization: use one organization per trust zone.
- Private keys stay in the agent's secret store. A remote agent keeps keys in its own
  network's secret manager (Azure Key Vault, AWS Secrets Manager or Google Secret Manager). The
  agent bundled with a single-server install uses the `LOCAL` store: AES-256-GCM encrypted files on
  a volume it shares with the server, keyed by `CERTPING_LOCAL_SECRET_KEY`. The database holds
  only references; the server reads a key from the store only to serve an audited download that
  includes it.
- Because the all-in-one and Compose installs share that store, key and volume between the server
  and the bundled agent, the server host can read every key the bundled agent holds. For
  certificates whose keys must not be readable there, run a separate agent in the target network
  with its own cloud secret manager, and do not use export or the bundled agent for those
  certificates. [Key custody and trust](architecture.md#key-custody-and-trust) has the details.

## First start

There is no built-in account or password. The all-in-one image, the Compose kit's `setup.sh` and
the Helm chart's `create-secret.sh` generate a first Platform Super Admin (`admin`) with a random
password per installation. The password is never written to the logs. To read it:

- all-in-one: `docker exec certping certping-admin` shows it;
- Compose: `setup.sh` keeps it in `.env` as `BOOTSTRAP_SUPER_ADMIN_PASSWORD`;
- Helm: it is the `BOOTSTRAP_SUPER_ADMIN_PASSWORD` key of the `certping` Secret.

The server creates that account at its first start with a forced password change, so the first
sign-in asks you for a new password. With the `BOOTSTRAP_SUPER_ADMIN_*` values empty or absent,
the web app instead sends the first visitor to a setup screen to create the admin by hand.
That screen has no setup token in 0.0.1-beta: whoever reaches it first becomes the admin. If you
install without the bootstrap values, keep the URL unreachable from untrusted networks until you
have finished setup ([First-run setup](architecture.md#first-run-setup)).

The first admin is also put in an organization at once, so every page is there at the first
sign-in: when none exists the server creates one (`CERTPING_ORGANIZATION_NAME`, default "My
organization"; `CERTPING_ORGANIZATION_DOMAIN`, default the host of `CERTPING_URL`), and when
exactly one exists the admin works in it. Rename it under Organization & Access. More
organizations can be added later; the admin switches between them with "Work in this
organization".

Then connect a DNS provider and add deployment targets (Integrations), issue a certificate
(Certificates) and invite members (Organization & Access, Members & roles). The Overview page
suggests next steps while the organization is empty. [getting-started.md](getting-started.md)
walks through each step.

Sign-in is local (username or email and password) with password reset by email once SMTP is
configured, or through one OpenID Connect provider for the installation (next sections).

### Single sign-on (OpenID Connect)

An installation can let people sign in with the identity provider they already use (Keycloak,
Authentik, Okta, Entra ID, Google Workspace, or any other OpenID Connect provider). It is one
provider for the whole installation, configured by the operator, with no administration screen:

1. At the provider, register a confidential web client with the redirect URI
   `<CERTPING_URL>/login/oauth2/code/sso` and note the issuer URL, client id and client secret.
2. Set `CERTPING_OIDC_ISSUER_URI`, `CERTPING_OIDC_CLIENT_ID`, `CERTPING_OIDC_CLIENT_SECRET` and
   `CERTPING_OIDC_ORGANIZATION` (the slug or id of the organization people are signed into) in
   `.env` (Compose) or `sso.oidc.*` plus the `CERTPING_OIDC_CLIENT_SECRET` key of the
   `certping` Secret (Helm), and restart the server. All four are needed; with any missing,
   sign-in stays local only.
3. The login page now shows "Continue with Single sign-on" (`CERTPING_OIDC_DISPLAY_NAME` renames
   it). The first time a person signs in, a member is created in that organization with the
   `CERTPING_OIDC_DEFAULT_ROLE` built-in role (`VIEWER` by default; `SUPER_ADMIN` is refused) and
   an organization admin raises it afterwards. Set `CERTPING_OIDC_AUTO_PROVISION=false` to let
   only members who were invited first (matched by email) use the provider.

The endpoints come from the issuer's discovery document, which the server fetches the first time
someone starts a sign-in. A person's email and name come from the provider; its groups are not
mapped to roles (group-based role mapping, SAML and SCIM are CertPing Enterprise features).
Members who signed in this way have the `SSO` sign-in method and no CertPing password; the first
Platform Super Admin is always a local account, so an identity provider outage never locks the
installation. Sign-ins and refusals are on the audit trail like local ones.

### Two-factor authentication

Every local account can add a time-based one-time password (TOTP) from Organization & Access,
Your account. Enrollment shows a key for an authenticator app (Google Authenticator, Microsoft
Authenticator, 1Password, Bitwarden or any RFC 6238 app) and is confirmed with one code; eight
single-use recovery codes are shown once. Sign-in then asks for a code after the password, and a
wrong code counts toward the account lockout like a wrong password. Turning it off needs the
password. An organization admin (or the Platform Super Admin) can reset a member's second factor
from the Members tab when both the app and the recovery codes are lost; the reset is audited as
`member.mfa_reset`.

The TOTP secret is stored sealed with the password pepper (`PASSWORD_PEPPER_V*`), so a database
backup alone cannot produce codes, and the sign-in challenge is signed with the same pepper, so it
works across replicas and restarts. Rotating the pepper re-seals secrets with the password hash
rotation job. Enforcing two-factor authentication for every member is on the roadmap.

## Protect the secrets of the installation

Some files of an installation are as sensitive as the private keys CertPing manages, and some
can be used to recover other secrets:

- `.env` (Compose) and the `certping` Secret (Helm) hold the database password, the JWT
  signing key, the password pepper that protects password hashes, the mail and reset-token
  secrets, the internal and agent tokens and `CERTPING_LOCAL_SECRET_KEY`, which decrypts every
  credential and private key in the local secret store.
- Database backups contain password hashes, agent token hashes, credential references and
  the audit log. Together with the pepper and the local secret key from `.env`, a backup
  reconstructs the whole installation, keys included.
- The secrets volume (`agent-secrets` in Compose, the `*-agent-secrets` PVC in Helm) holds
  the encrypted private keys and credentials of the bundled agent.

So:

- Never commit, paste, upload or email these files. `.env` is in `.gitignore` to stop accidental
  commits.
- Store backups encrypted, with access limited to the people who restore them, and keep the
  `.env` or Secret backup separate from the database backup.
- Treat suspected exposure of any of them as a key compromise: rotate the database password, the
  JWT key, the tokens and the affected credentials, and re-issue certificates whose keys were in
  the local store. The password pepper is versioned (`PASSWORD_PEPPER_ACTIVE_VERSION`): add a new
  version, make it active and run the password-hash rotation job (`/api/v1/admin/password-hash`,
  super admin only) to re-wrap the hashes. `CERTPING_LOCAL_SECRET_KEY` cannot be rotated in
  place yet; an exposure of it means re-creating the local store's contents.
- Mailpit (`docker compose --profile mailpit`) is a development mail catcher: it stores every
  message in plain text and has no authentication. Use it only on a laptop, never expose its
  port, and configure a real SMTP server for anything else.

## Pin the version you run

Run a release tag, never `latest`. `latest` changes under you and cannot be audited later. The
first public release is `0.0.1-beta`. The kits default to it: the Helm charts use the chart's
`appVersion`, and Compose uses `CERTPING_VERSION` from `.env`, which defaults to `0.0.1-beta`. For local
development builds use the tag `dev` (`CERTPING_VERSION=dev docker compose build`, and
`--build-arg CERTPING_VERSION=dev` for the all-in-one image) so they never mix with a release.
For a server you keep:

- Set `CERTPING_VERSION` in `.env` (Compose) or `image.tag` in `values.yaml` (Helm) to a release
  tag such as `0.0.1-beta`, and upgrade deliberately with `docker compose pull && docker
  compose up -d` or `helm upgrade`.
- Pinning by digest (`ghcr.io/certping-labs/certping-server@sha256:...`) is stricter. Take the
  digest from the release notes or `release-metadata.json` of the release you verified.
- Releases carry Sigstore signatures and build provenance; how to
  verify them before pinning is in [Verifying a release](../.github/RELEASING.md#verifying-a-release). An image
  is only as trustworthy as that verification; the kits do not verify signatures for you.

## Upgrading

Every release is a new set of images, and the server migrates the database forward when it
starts. Back up first: a restore of that backup with the old images is the only rollback. The
steps for each kit are in [operations.md](operations.md#upgrade-certping).

## Running behind your own reverse proxy

The Compose kit ships Caddy as the only public port, with automatic TLS for the name you give
`setup.sh`. To put CertPing behind a proxy you already run (nginx, Traefik, HAProxy, a cloud
load balancer):

- Terminate TLS at your proxy and forward to the kit's proxy over HTTP, or remove the `proxy`
  service and route the paths the kit's `Caddyfile` routes: `/api/*`, `/.well-known/*`,
  `/oauth2/*` and `/login/oauth2/*` to `server:8080`, everything else to `web:3000`. The web app calls the API on its own origin, so
  both must be served from the same host name.
- Set `CERTPING_URL` to the public URL. It is what the web app, password-reset emails and remote
  agents use; a wrong value shows up first as agents that cannot connect.
- Pass `X-Forwarded-For` and `X-Forwarded-Proto`. The audit trail records the client address from
  the rightmost `X-Forwarded-For` entry, the one your proxy appended (`CERTPING_CLIENT_IP_SOURCE`,
  default `LAST_PROXY_HOP`), so a client cannot spoof it by sending the header itself.
- Allow read timeouts of at least 60 seconds on `/api/*`: agents long-poll the gateway, and the
  server holds a poll open for up to 25 seconds. Allow request bodies of a few megabytes for certificate bundles.
- Serving CertPing under a sub-path (`https://tools.example.com/certping/`) is not supported;
  use a host name of its own.

## What to back up

The PostgreSQL database, the generated secrets (`config.env`, `.env` or the `certping` Secret)
and the bundled agent's secrets volume. A database backup without the secrets cannot be
restored. Commands for each kit are in [operations.md](operations.md#back-up-and-restore).

## Privacy and telemetry

What a self-hosted CertPing sends out of your environment, what it never
sends, and the settings that control it. This page describes the open-source
product in this repository as of the code it ships with; the hosted CertPing
service at certping.com has its own
[privacy policy](https://www.certping.com/privacy-policy/) and
[terms](https://www.certping.com/terms/).

### Summary

A self-hosted installation sends no product telemetry by default. The web app
contains no analytics code, and the server's usage report is opt-in
(`CERTPING_TELEMETRY_ENABLED`, default false), with every field listed below.

The only outbound connections a default installation makes are the ones its
job needs: your certificate authority (for example Let's Encrypt or the CA
you configure), your DNS provider, the systems certificates are deployed to,
your mail server if you configure one, the chat and incident tools an
organization adds (Slack, Teams, PagerDuty, ServiceNow), CertPing's DNS API if
you use the CertPing DNS provider, and container registries when you pull
images. Certificate contents, private keys, credentials, secret values and your
users' data are never sent to Seaionl Inc. Where private keys are kept inside
your installation, and which processes can read them, is in
[Key custody and trust](architecture.md#key-custody-and-trust).

### Web app

The web app has no analytics and no tracking code. The browser calls only your
CertPing server's API. The cookies and browser storage it uses are for sign-in
and screen preferences.

### Opt-in usage report (server)

The server can send a small usage report to Seaionl Inc. once a day. It is
off by default and stays off until the operator sets
`CERTPING_TELEMETRY_ENABLED=true`. The server logs at startup whether it is on
or off, and `GET /api/v1/admin/telemetry` (Platform Super Admin) shows the
exact report this installation would send, so you can read it before opting
in. The purpose is to count installations and sizes so the project knows what
to test and support; nothing in it identifies your company, your people or
your certificates.

The report has these fields (`TelemetryReport` in the server, schema
`certping.telemetry.v1`):

- `installationId`: a random UUID minted the first time the server starts
  (table `installation`). It is not derived from anything about your
  installation; delete the row to get a new one.
- `reportedAt`, `version` (the server's release version, or `unknown` for a
  development build), `edition` (`open`).
- `runtime`: Java version, operating system name and architecture, database
  product and major version (for example `PostgreSQL 16`).
- `counts`: the number of organizations, users, users with two-factor
  authentication, certificates, discovered certificates and deployment
  targets. Numbers only.

The report never contains hostnames, URLs, domain names, certificate contents
or serials, email addresses, names, organization names, tokens, credentials,
IP addresses of your systems, or anything typed by a user. The receiving
endpoint sees the sending server's public IP address as part of the HTTP
request, as any request does; it is not part of the report body.

It goes to `CERTPING_TELEMETRY_ENDPOINT`, by default
`https://telemetry.certping.com/v1/report`, operated by Seaionl Inc. Until that
service is live, an opted-in installation's report is refused and dropped
quietly; a failed send is logged at debug level and tried again at the next
interval (`CERTPING_TELEMETRY_INTERVAL`, default 24 hours, after an initial
delay of one hour).

To keep it off, leave `CERTPING_TELEMETRY_ENABLED` unset or set it to `false`
(the default in every kit). Adding a field to the report is a change to this page
and to the changelog, never a silent one.

### Server, agent and notifier

Apart from the opt-in report above, the Java services send no usage or product
telemetry anywhere.

- Tracing and metrics: the images carry the OpenTelemetry Java agent, but
  it is off unless `OTEL_JAVAAGENT_ENABLED=true` and an
  `OTEL_EXPORTER_OTLP_ENDPOINT` of yours are set; the kits default both to
  off. When you turn it on, traces and metrics go only to the endpoint you
  name.
- Health endpoints (`/actuator/health` on each service) answer callers
  inside the installation; the kits do not route them through the public URL,
  and nothing is pushed. 0.0.1-beta has no Prometheus endpoint.
- Agents connect outbound to your CertPing server only (plus the CA, DNS
  and deployment systems they work with). They call Seaionl Inc. only when you
  choose the CertPing DNS provider: then the agent sends the validation
  record names and values to CertPing's DNS API.
- Mail: the notifier sends email only through the SMTP server you
  configure, to the recipients your organization set.
- Audit log: the server records who did what, when, with the request's
  source IP address and user agent, in your database. That record is for your
  operators and never leaves your installation.

### Recommended settings for enterprise and regulated deployments

- Leave `CERTPING_TELEMETRY_ENABLED` unset.
- Send traces and metrics to your own collector or not at all.
- Run the proxy with TLS (the Compose kit uses Caddy; use your own
  certificate for an internal hostname), and restrict the actuator and
  metrics endpoints to your monitoring network.
- Keep the database, Valkey and the secret volume on encrypted storage with
  restricted access, and set a retention period for the audit log that
  matches your policy (a Platform Super Admin sets it on the Audit tab of
  Organization & Access).
- Treat `.env` files, Helm Secrets, database backups and the local secret
  store volume as highly sensitive; see
  [Protect the secrets of the installation](#protect-the-secrets-of-the-installation).

### Your responsibilities as an operator

CertPing is software you run. You are the controller of the data in it. Legal
notices to your users, privacy and cookie notices, retention policies, access
control, backup handling, breach procedures and regulatory compliance (for
example GDPR, HIPAA or sector rules) are yours to put in place; the project
provides the controls described above and documents their defaults, and does
not make compliance claims on your behalf.
