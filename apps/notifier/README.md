# CertPing notifier

The notifier delivers CertPing's notifications. It long-polls the server's
agent gateway (`/api/v1/agent-gateway`, the `notifications` channel) with the
internal token, renders each message from a template and sends it. Before it
emails an organization it asks the server over internal gRPC whether that
organization turned the notification off. It records every delivery in
PostgreSQL.

No inbound connection from outside the installation is needed.

## Settings

| Variable | Purpose |
| --- | --- |
| `CERTPING_INTERNAL_URL` | The server the notifier polls, for example `http://server:8080` (`selfhosted` profile). |
| `CERTPING_INTERNAL_TOKEN` | Shared secret for the notifications channel. Same value as on the server. |
| `CERT_MANAGER_GRPC_ADDR` | The server's internal gRPC address, for example `server:50051`. |
| `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | PostgreSQL for delivery records. |
| `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_SMTP_AUTH`, `MAIL_STARTTLS` | Your SMTP server. |
| `EMAIL_FROM` | Sender address. |
| `NOTIFIER_REPLAY_TOKEN` | Enables `POST /api/notifications/admin/replay-undelivered` (header `X-Notifier-Replay-Token`). Empty means the endpoint is off. |

`src/main/resources/application.yaml` lists every setting and its default.

## Failed deliveries

A failed email stays in `notification_records` under the publisher's request
ID. Every hour the notifier replays up to 50 failed requests whose last attempt
is at least an hour old, at most three times each. A recipient whose address is
refused for good is given up on alone; the other recipients still get the
email. The gauge `notification.deliver_once.undelivered.open` counts open
requests from the last 30 days. Every pod exports the same count from the same
database, so alert on `max()`, not `sum()`.

## Develop

```bash
make notifier-ci   # from the repository root: build and test
```

To run it with the rest of the stack, use the Compose kit
([deploy/compose](../../deploy/compose/README.md)); its `mailpit` profile
catches email locally.
