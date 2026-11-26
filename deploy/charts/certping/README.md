# certping Helm chart

Installs CertPing on Kubernetes: the server, the web app, the notifier and,
by default, a bundled agent. For agents in other clusters or networks, use the
[certping-agent](../certping-agent/README.md) chart.

## Install

You need Helm 3, `kubectl`, `openssl`, an Ingress controller and a DNS name.

```bash
cd deploy/charts/certping

# 1. Once: create the Secret with fresh random keys and passwords.
./create-secret.sh certping.example.com certping

# 2. Install.
helm install certping . -n certping --create-namespace \
  --set url=https://certping.example.com
```

`create-secret.sh <domain> [namespace] [secret-name]` creates the Secret
`certping` (or the name you pass). It refuses to replace a Secret that exists,
because its keys must never change. It holds the database and Valkey
passwords, the password pepper, the JWT signing key, the agent gateway and
secret-store keys, and the first admin's password. The server reads every key.

Sign in as `admin`. The first password is never logged; read it from the
Secret:

```bash
kubectl -n certping get secret certping \
  -o jsonpath='{.data.BOOTSTRAP_SUPER_ADMIN_PASSWORD}' | base64 -d; echo
```

You choose a new password at the first sign-in.

## Required values

| Value | Purpose |
| --- | --- |
| `url` | Public URL people and remote agents use. The Ingress serves this host. |
| `existingSecret` | The Secret from `create-secret.sh`. Default `certping`. |

Common optional values:

| Value | Default | Purpose |
| --- | --- | --- |
| `image.tag` | the chart's `appVersion` | Image version. Pin it, or pin digests. |
| `ingress.className`, `ingress.annotations`, `ingress.tlsSecretName` | empty | Ingress settings and the TLS Secret for the host. |
| `notifier.mail.host`, `.port`, `.username`, `.from` | empty, `587` | SMTP. Put the password in the Secret as `MAIL_PASSWORD`. |
| `notifier.mail.starttls`, `notifier.mail.smtpAuth` | `true`, `true` | `MAIL_STARTTLS` and `MAIL_SMTP_AUTH`. Set both `false` for a relay without TLS or sign-in. |
| `sso.oidc.*` | empty | One OpenID Connect provider. Put the client secret in the Secret as `CERTPING_OIDC_CLIENT_SECRET`. See [docs/self-hosting.md](../../../docs/self-hosting.md#single-sign-on-openid-connect). |
| `bundledAgent.enabled` | `true` | The agent beside the server, with the `LOCAL` secret store on a ReadWriteOnce volume. Turn it off when every agent runs elsewhere. While it is on, `server.replicas` must stay at 1 (the chart refuses more). |
| `bundledAgent.acme.directoryUrl`, `bundledAgent.acme.accountEmail` | Let's Encrypt production, empty | The bundled agent's ACME CA and account contact. |
| `bundledAgent.acme.eab.keyId` | empty | External account binding for a CA that requires it (ZeroSSL, Google Trust Services, SSL.com). Add the HMAC key to the Secret as `ACME_EAB_HMAC_KEY`. |
| `extraCaCerts.configMap` or `extraCaCerts.secret`, `extraCaCerts.key` | empty, `ca.crt` | A PEM file of extra CA certificates trusted by the server, notifier and bundled agent. |
| `server.extraEnv`, `web.extraEnv`, `notifier.extraEnv`, `bundledAgent.extraEnv` (and `extraEnvFrom` for each) | empty | Any other variable for that container. |
| `bootstrapAgentOrganization` | empty | Organization slug of the bundled agent; empty means the first one. |

`values.yaml` documents every value.

## PostgreSQL

The chart's own PostgreSQL (`postgres.enabled: true`) is a single pod for
evaluation. **For production, use an external PostgreSQL 14 or newer**: a
managed database or one run by an operator, with backups you have tested.

```yaml
postgres:
  enabled: false
database:
  host: postgres.example.internal
  port: 5432
  name: certping
  username: certping
# DB_PASSWORD comes from the Secret.
```

Size `max_connections` for `server.replicas` x `server.dbPoolSize` (default
40), plus 10 per notifier replica, plus headroom.

## Valkey

The bundled store is Valkey (Redis compatible) and requires the
`REDIS_PASSWORD` key of the Secret. To use your own Redis or Valkey, set
`redis.host` and `redis.enabled: false`; the value names keep the word redis.

## NetworkPolicy

`networkPolicy.enabled` is `true` by default. It needs a CNI that enforces
NetworkPolicy. It limits inbound traffic only:

- PostgreSQL 5432 from the server and the notifier;
- Valkey 6379 from the server;
- the server's internal gRPC port 50051 from the notifier only (it has no
  caller authentication);
- the notifier 8080 from the server;
- the server 8080 and web 3000 from `networkPolicy.ingressFrom`, the web pods
  and the notifier. With `ingressFrom` empty, from anywhere.

Set `ingressFrom` to your ingress controller, for example:

```yaml
networkPolicy:
  ingressFrom:
    - namespaceSelector:
        matchLabels: { kubernetes.io/metadata.name: ingress-nginx }
```

Egress is not restricted, because the server and agents call CAs, DNS
providers, cloud APIs and SMTP servers that cannot be listed in advance.

## Upgrade

1. Read the release notes for every version between yours and the target.
2. Back up the database, the Secret and the bundled agent's secrets volume.
3. `helm upgrade certping . -n certping -f your-values.yaml --set image.tag=<version>`

The server runs database migrations at startup. They are forward-only, so the
rollback is a restore of the backup with the old images. Keep the same Secret
across upgrades.

A Secret made by an older `create-secret.sh` may lack `REDIS_PASSWORD`. Add it
before upgrading:

```bash
kubectl -n certping patch secret certping --type merge \
  -p "{\"stringData\":{\"REDIS_PASSWORD\":\"$(openssl rand -hex 32)\"}}"
```

More in [docs/self-hosting.md](../../../docs/self-hosting.md#upgrading).
