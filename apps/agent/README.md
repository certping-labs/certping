# CertPing agent

The agent does every outside job for CertPing: certificate orders with CAs,
DNS challenges, deployments and discovery scans. It runs inside your network,
creates and keeps the private keys, and only makes outbound HTTPS calls to the
CertPing server. Nothing connects into it.

## Documentation

- [docs/architecture.md](../../docs/architecture.md): how the agent, server, notifier and web app
  connect, and the agent gateway.
- [docs/self-hosting.md](../../docs/self-hosting.md): running the bundled agent and agents in
  other networks (Compose, Helm).
- [deploy/charts/certping-agent](../../deploy/charts/certping-agent/README.md): the agent Helm chart.
- Reference: [deployment targets](../../docs/integrations.md#deployment-target-permissions) (permissions and
  Kubernetes behaviour), [Kubernetes discovery](../../docs/integrations.md#kubernetes-discovery) and
  [machine identity](../../docs/integrations.md#machine-identity-experimental).

## How it gets work

1. The server writes a job (issue, renew, deploy, discover) to its PostgreSQL `message_queue`
   table.
2. The agent long-polls the server's agent gateway (`/api/v1/agent-gateway`) with its agent
   token. Each poll asks to wait 20 seconds; the server caps a poll at 25 seconds.
3. The agent does the job, keeps renewing its hold on it while it works, and sends the result
   back through the gateway.

The agent token decides which organization the agent works for. Create one in the web app:
**Agents**, then **Add agent**. The token is shown once. The same page shows each agent's
status and the settings it reports.

## Where keys and credentials live

`AGENT_SECRET_STORE_PROVIDER` picks the secret store:

| Value | Store |
| --- | --- |
| `LOCAL` | AES-256-GCM encrypted files in `CERTPING_LOCAL_SECRET_DIR`, keyed by `CERTPING_LOCAL_SECRET_KEY`. Used by the agent bundled with a single-server install. |
| `AZURE_KV` | Your Azure Key Vault (`CLIENT_KV_URI`, `AZURE_KV_AUTH_MODE`). |
| `AWS_SECRETS_MANAGER` | Your AWS Secrets Manager (`AWS_REGION`, `AWS_SM_AUTH_MODE`). |
| `GCP_SECRET_MANAGER` | Your Google Secret Manager (`GCP_PROJECT_ID`, `GCP_SM_AUTH_MODE`). |

Provider credentials (DNS, cloud, CA) are either a reference to a secret in that store, or typed
into the web app once and written straight to the store. Private keys are not stored in the
server's database; it keeps a reference.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `CERTPING_SERVER_URL` | none | The CertPing URL the agent connects to. Required. |
| `CERTPING_AGENT_TOKEN` | none | The agent token. Required. |
| `AGENT_SECRET_STORE_PROVIDER` | `LOCAL` | `LOCAL`, `AZURE_KV`, `AWS_SECRETS_MANAGER` or `GCP_SECRET_MANAGER`. |
| `CERTPING_AGENT_MAX_CONCURRENT_JOBS` | `8` | Jobs handled at the same time. |
| `CERTPING_AGENT_MAX_LOCK_RENEWAL` | `30m` | How long a job's hold is kept renewed. |
| `ACME_DIRECTORY_URL` | see `application.yml` | ACME directory for ACME issuance. |
| `ACME_ACCOUNT_EMAIL` | empty | ACME account contact. |
| `HTTPS_PROXY` | empty | Proxy for the connection to the CertPing server. Calls to CAs, DNS and cloud APIs do not read it. |

`src/main/resources/application.yml` and `application-selfhosted.yml` list every setting and its
default. The image runs with `SPRING_PROFILES_ACTIVE=selfhosted` by default. Installing agents in other
networks, workload identity and sizing: [docs/agents.md](../../docs/agents.md).

## Namecheap DNS

Set `dnsProvider` to `NAMECHEAP`. The secret referenced by `dnsCredentialPath` must contain:

```json
{
  "apiUser": "namecheap-api-user",
  "apiKey": "namecheap-api-key",
  "username": "namecheap-username"
}
```

The agent reads the public IP that Namecheap has allowlisted from `NAMECHEAP_CLIENT_IP`.
Namecheap's `setHosts` API replaces the complete DNS record set, so the agent first fetches all
existing records, adds or removes only the matching validation TXT record, and then submits the
complete list.

## Develop

```bash
make agent-ci    # from the repository root: build and test
```

To run the agent against a full local stack, use the Compose kit
([deploy/compose](../../deploy/compose/README.md)) or the end-to-end lab
([deploy/e2e-lab](../../deploy/e2e-lab/README.md)).
