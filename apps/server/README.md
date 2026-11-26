# CertPing server

The server is CertPing's API and holds its state and logic: sign-in,
organizations and roles, certificate records, the scheduler, the job queue, the agent gateway,
the audit log and PQC readiness. It is a Spring Boot 4 service on Java 25 with
PostgreSQL (Flyway migrations) and Valkey (Redis compatible) for signed-out
tokens and short caches.

## Documentation

- [docs/architecture.md](../../docs/architecture.md): how the server, agents, notifier and web
  app connect.
- [docs/self-hosting.md](../../docs/self-hosting.md): installing, first start, single sign-on,
  upgrades and backups.
- [JWT signing keys](../../docs/operations.md#jwt-signing-keys): creating and rotating them.
- [Internal gRPC](../../docs/architecture.md#internal-grpc): the service the notifier calls.
- [Queue depth alerts](../../docs/operations.md#watch-the-queue-and-the-agents): optional alerts
  on message queue depth.
- Discovery: [Discovery](../../docs/architecture.md#discovery) and
  [Kubernetes discovery](../../docs/integrations.md#kubernetes-discovery).
- [Machine identity](../../docs/integrations.md#machine-identity-experimental) (experimental).

## Agent gateway

Agents and the notifier never connect to a broker. The server keeps jobs in the PostgreSQL
`message_queue` table and serves them over HTTPS at `/api/v1/agent-gateway`:

- Agents authenticate with per-organization agent tokens (`cpa_...`, stored as SHA-256 hashes,
  revocable from the web app). The notifier uses the internal token (`CERTPING_INTERNAL_TOKEN`).
- The server stamps every inbound message with the organization the token proved. Processors
  trust that stamp, never the message body.
- A receive call is a long poll. Clients ask for 20 seconds; the server caps a poll at 25
  seconds.
- Limits per token (`CERTPING_TRANSPORT_MAX_CONCURRENT_POLLS_PER_TOKEN`,
  `CERTPING_TRANSPORT_MAX_REQUESTS_PER_TOKEN_PER_MINUTE` and others in `application.yaml`)
  answer 429 with `Retry-After`.

## First administrator

A fresh installation has no users. Either the web app sends the first visitor to a setup screen
(`POST /api/auth/setup`, answered only while no user exists), or the installer sets the
`BOOTSTRAP_SUPER_ADMIN_USERNAME`, `BOOTSTRAP_SUPER_ADMIN_EMAIL` and
`BOOTSTRAP_SUPER_ADMIN_PASSWORD` settings. They have no defaults. The account is created with a
forced password change.

## Roles

Four built-in roles: Platform Super Admin, Organization Admin, Security Analyst and Viewer. The
Platform Super Admin administers the installation and its organizations. Organization Admins
manage members, roles and credentials in their own organization and cannot grant Platform Super
Admin.

## Settings

Configuration comes from environment variables. `src/main/resources/application.yaml` lists every
setting and its default. Settings that matter for security:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CERTPING_RATE_LIMIT_AUTH_MAX_REQUESTS` | `20` | Sign-in, MFA, password reset and SSO code exchange requests per client address per window. |
| `CERTPING_RATE_LIMIT_AUTH_WINDOW` | `PT5M` | The rate limit window. |
| `CERTPING_CLIENT_IP_SOURCE` | `LAST_PROXY_HOP` | Which address the audit log records as the client. |
| `REDIS_HOST`, `REDIS_PASSWORD` | `localhost`, none | The Valkey (Redis compatible) server and its password. |
| `CERTPING_TELEMETRY_ENABLED` | `false` | The opt-in usage report ([docs/self-hosting.md#privacy-and-telemetry](../../docs/self-hosting.md#privacy-and-telemetry)). |

## Develop

```bash
make server-ci   # from the repository root: build and test
```

The integration tests use Testcontainers, so Docker must be running. To run the server with the
rest of the stack, use the Compose kit ([deploy/compose](../../deploy/compose/README.md)) or the
end-to-end lab ([deploy/e2e-lab](../../deploy/e2e-lab/README.md)).
