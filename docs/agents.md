# Agents

An agent does CertPing's outside work: ACME and CA orders, DNS records, deployments and
discovery scans. It generates the private keys and keeps them in its secret store. It connects to
the server's agent gateway over outbound HTTPS and opens no port that anything connects to, unless
you turn on its SCEP endpoint for devices ([The SCEP endpoint](integrations.md#the-scep-endpoint)).

Every install kit runs one bundled agent next to the server. This page is about running more.

## When to run another agent

Run another agent when a target is out of the bundled agent's reach: a cluster, a VPC, a data
center or a customer site behind a firewall. Run one also when private keys must stay in another
network, because the agent there keeps them in that network's own secret manager. The bundled
agent shares its key store with the server, so the server host can read its keys; a separate agent
with a cloud secret manager does not ([Key custody and trust](architecture.md#key-custody-and-trust)).

Throughput is a weaker reason. One agent handles 8 jobs at a time by default, and in the lab load
test that was enough to issue or renew 1,000 certificates in 3 to 4 minutes on one all-in-one
container with 4 GB of memory. Raising the agent's concurrency is usually simpler than adding
agents ([sizing](#sizing-and-concurrency), and [operations.md](operations.md#plan-for-more-certificates)
for the test).

### How agents share work

All agents of one organization take jobs from the same queue, and any of them may take any job.
In 0.0.1-beta there is no way to send a job to a particular agent. So:

- Give every agent in an organization the same reach: the same networks, the same secret store
  and the same credentials.
- Treat every agent token as trusted for the whole organization. Any agent of an organization
  can receive any job of that organization, including its credential handles, and post its
  result. Use one organization per trust zone, and never put a lab agent in an organization
  with production certificates ([Trust model of agent tokens](architecture.md#trust-model-of-agent-tokens)).
- For networks that cannot reach each other, use one organization per network, each with its own
  agent. Set `CERTPING_BOOTSTRAP_AGENT_ORG` (Compose, all-in-one) or `bootstrapAgentOrganization`
  (Helm) to choose which organization the bundled agent works for, and turn the bundled agent off
  in Helm (`bundledAgent.enabled: false`) when every agent runs elsewhere.

## The Agents page

**Agents** in the sidebar (`/agents`) lists every agent of the organization with **Name**,
**Status** (**Online**, **Offline**, **Never connected** or **Revoked**), **Last seen**,
**Version**, **Host**, **Secret store** and **Token expires**. The agent next to the server is
tagged **Bundled**. Select an agent to see what it reports about itself:

- **Connection**: status, last seen, host, OS, Java, version, and whether a proxy is set.
- **Settings**: secret store, **Jobs at once**, **ACME CA**, **Account email**, and whether
  GlobalSign is set up on it.
- **Can do**: the deployment targets, discovery targets and DNS providers it supports.

These values are read from the agent and never include a secret. To change one, set the agent's
environment variable ([configuration.md](configuration.md#agent)) and restart it. The same panel
has **Run health check** and **Revoke token**. A health check goes to the organization's queue,
so any of its agents may answer it.

The page needs the permission to manage the organization. The API behind it is
`GET /api/v1/agents`. The **Agents** card on the organization page (**Organization & Access**,
**Organization**) lists the same tokens and links here with **Manage agents**.

## Create an agent token

1. Open **Agents** and select **Add agent**.
2. Give it a **Name** (for example `datacenter-east`), choose **Where should this agent keep
   keys?** (AWS Secrets Manager, Azure Key Vault or Google Secret Manager) and **Token expires
   after** (**Never** or a number of days), then select **Create token**. In the API,
   `POST /api/v1/agent-tokens` takes an optional `expiresInDays` from 1 to 3650.
3. Copy the **Agent token** (`cpa_...`). It is shown once. Below it are two ready commands for
   the store you chose: **Start the agent with Docker** and **Install the agent with Helm**.
   Replace the values in angle brackets.

The commands use the server's own version as the image tag (`CERTPING_VERSION` on the server, see
[configuration.md](configuration.md#url-proxy-and-tls)) and the cloud identity of the host: no
cloud secret goes in them.

The token decides which organization the agent works for. The server keeps only its SHA-256
hash. The page shows every token with **Last seen**, the last time an agent used it, and its
expiry date. An expired token gets `401` on its next call; create a new token and restart the
agent with it before the old one expires. The bundled agent's bootstrap token never expires. The
server records which token delivered each applied result (table `agent_result_receipts`).
Creating and revoking a token are recorded in the audit log as `agent_token.created` and
`agent_token.revoked`.

## Choose a secret store

The agent keeps private keys, ACME account keys and stored credentials in one secret store,
chosen with `AGENT_SECRET_STORE_PROVIDER`:

| Store | Value | Settings | Auth modes |
| --- | --- | --- | --- |
| Azure Key Vault | `AZURE_KV` | `CLIENT_KV_URI` | `AZURE_KV_AUTH_MODE`: `WORKLOAD_IDENTITY`, `CLIENT_SECRET`, `CLIENT_CERTIFICATE`, `DEFAULT` (the Azure SDK's default chain) |
| AWS Secrets Manager | `AWS_SECRETS_MANAGER` | `AWS_REGION` | `AWS_SM_AUTH_MODE`: `DEFAULT` (the AWS SDK's default chain), `WEB_IDENTITY_TOKEN`, `INSTANCE_PROFILE`, `PROFILE`, `STATIC` |
| Google Secret Manager | `GCP_SECRET_MANAGER` | `GCP_PROJECT_ID` | `GCP_SM_AUTH_MODE`: `ADC` (application default credentials), `WORKLOAD_IDENTITY_FEDERATION`, `SA_JSON` |
| Local files | `LOCAL` | `CERTPING_LOCAL_SECRET_DIR`, `CERTPING_LOCAL_SECRET_KEY` | For the bundled agent, which shares the directory and key with the server. The `certping-agent` chart refuses it. |

The agent creates, reads, updates and deletes secrets in the store, so its identity needs read
and write access to secrets there: for example Key Vault Secrets Officer on the vault, or
`secretsmanager:CreateSecret`, `GetSecretValue`, `PutSecretValue` and `DeleteSecret` on secrets
named `certping/*` in AWS. On AWS the agent deletes with a 7-day recovery window.

A credential pasted into the web form is written by the server into the server's own store
(`LOCAL` on the single-server kits), which a remote agent cannot read. For a remote agent, create
credentials with **Agent identity or my own vault** ([Credentials](architecture.md#credentials)).

## Run as a container (any VM or host with Docker)

The agent is published as a container image, `ghcr.io/certping-labs/certping-agent`, for amd64
and arm64. There is no separate binary or OS package. Use the same version as the server.

```sh
docker run -d --name certping-agent --restart unless-stopped \
  -e SPRING_PROFILES_ACTIVE=selfhosted \
  -e CERTPING_SERVER_URL=https://certping.example.com \
  -e CERTPING_AGENT_TOKEN=cpa_... \
  -e AGENT_SECRET_STORE_PROVIDER=AWS_SECRETS_MANAGER \
  -e AWS_REGION=eu-west-1 \
  -e AWS_SM_AUTH_MODE=DEFAULT \
  ghcr.io/certping-labs/certping-agent:0.0.1-beta
docker logs -f certping-agent
```

The image starts with the OpenTelemetry Java agent off. To export traces, set
`OTEL_JAVAAGENT_ENABLED=true` and `OTEL_EXPORTER_OTLP_ENDPOINT` to your collector.

On an EC2 instance with an instance profile, `DEFAULT` finds the instance role. For Azure Key
Vault use `-e AGENT_SECRET_STORE_PROVIDER=AZURE_KV -e CLIENT_KV_URI=https://<vault>.vault.azure.net`;
for Google Secret Manager `-e AGENT_SECRET_STORE_PROVIDER=GCP_SECRET_MANAGER -e GCP_PROJECT_ID=<project>`.

The released image uses the `selfhosted` profile by default. Keep that profile so the agent
reads the ACME and secret store settings.

A good start logs `Connected to the CertPing agent gateway: organizationId=...` and
`SecretStore active: provider=...`, and the agent shows **Online** on the **Agents** page. The agent
checks its secret store at startup and stops if it cannot reach it: with `AWS_SECRETS_MANAGER` and
no AWS identity on the host, it exits with `Failed to resolve caller identity via STS`.

## Run on Kubernetes with the certping-agent chart

```sh
kubectl create namespace certping-agent
kubectl -n certping-agent create secret generic certping-agent-token \
  --from-literal=token=cpa_...
helm install edge oci://ghcr.io/certping-labs/charts/certping-agent \
  --version 0.0.1-beta -n certping-agent \
  --set serverUrl=https://certping.example.com \
  -f my-agent-values.yaml
```

The chart's values and defaults are in [deploy/charts/certping-agent](../deploy/charts/certping-agent/README.md).
The examples of `my-agent-values.yaml` below use workload identity, so no cloud secret is stored
anywhere.

### Azure workload identity (AKS)

```yaml
secretStore:
  provider: AZURE_KV
  azureKv:
    vaultUri: https://my-vault.vault.azure.net
    authMode: WORKLOAD_IDENTITY
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000
podLabels:
  azure.workload.identity/use: "true"
```

The managed identity or app registration needs a federated credential for the service account
`system:serviceaccount:certping-agent:edge-certping-agent` (release name plus
`-certping-agent`).

### AWS IAM roles for service accounts (EKS)

```yaml
secretStore:
  provider: AWS_SECRETS_MANAGER
  awsSecretsManager:
    region: eu-west-1
    authMode: DEFAULT
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/certping-agent
```

`authMode: DEFAULT` is the chart's default: the AWS default chain picks up the role and token
file that EKS injects. `WEB_IDENTITY_TOKEN` also needs the role ARN and token file, which the
chart does not set; give them with `extraEnv` as `AGENT_SECRETSTORE_AWSSECRETSMANAGER_ROLEARN` and
`AGENT_SECRETSTORE_AWSSECRETSMANAGER_WEBIDENTITYTOKENFILE`.

### GKE workload identity

```yaml
secretStore:
  provider: GCP_SECRET_MANAGER
  gcpSecretManager:
    projectId: my-project
    authMode: ADC
serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: certping-agent@my-project.iam.gserviceaccount.com
```

The Google service account needs Secret Manager access in the project, and an IAM binding that
lets the Kubernetes service account impersonate it.

### Deploy and discover in the agent's own cluster

An agent inside a cluster can deploy and discover there with its own service account. Create the Kubernetes credential with auth method
**Service Account (In-Cluster)**, and grant the chart's service account the RBAC in
[Deployment target permissions](integrations.md#deployment-target-permissions)
(deployment) and [Kubernetes discovery](integrations.md#kubernetes-discovery)
(discovery).

## Networking

The agent needs no inbound connection, except to its SCEP endpoint when that is on. Outbound, it
needs:

| Destination | Port | Why |
| --- | --- | --- |
| Your `CERTPING_URL` | 443 | The agent gateway. Each poll waits up to 20 seconds; proxies in between must allow at least 60 seconds of read time. |
| Your ACME CA, for example `acme-v02.api.letsencrypt.org` | 443 | Orders. |
| Your DNS provider's API, for example `api.cloudflare.com` | 443 | Writing and deleting the TXT record. |
| The authoritative nameservers of each domain | 53 | The agent checks that the TXT record is visible on every nameserver of the zone before the CA validates. |
| Cloud and target APIs: AWS, Azure, Google, Kubernetes API servers (often 6443), Akamai, F5 | varies | Deployment and discovery. |
| Your secret store's endpoint | 443 | Keys and credentials. |

`HTTPS_PROXY` (or `https_proxy`) is honoured for the connection to the CertPing server. Calls to
CAs, DNS providers and cloud APIs do not read that variable. Proxy support for those depends on
each client library and is not tested.

To trust a private CA (an internal ACME server, a TLS-inspecting proxy, a CertPing server behind
a private CA), give it as a PEM file:

- `certping-agent` chart: put the PEM in a ConfigMap or Secret and set `extraCaCerts.configMap`
  or `extraCaCerts.secret` (key `extraCaCerts.key`, default `ca.crt`).
- Compose and the all-in-one: `CERTPING_EXTRA_CA_CERTS`
  ([configuration.md](configuration.md#url-proxy-and-tls)).
- A plain `docker run` of the agent image: the image itself does not read
  `CERTPING_EXTRA_CA_CERTS`. Do what Compose does: mount `deploy/compose/java-entrypoint.sh` and
  the PEM, set `CERTPING_EXTRA_CA_CERTS` to the PEM's path in the container, and start with
  `--entrypoint /bin/sh` and the script's path as the command.

## Sizing and concurrency

| Setting | Default | Notes |
| --- | --- | --- |
| `CERTPING_AGENT_MAX_CONCURRENT_JOBS` | `8` | One gateway poller per job slot. Most job time is waiting on CAs and DNS, so more slots raise throughput until a provider rate limit is reached. |
| Server: `CERTPING_TRANSPORT_MAX_CONCURRENT_POLLS_PER_TOKEN` | `8` | Open polls the server allows per token. Raise it with the agent's concurrency, or the extra pollers get `429` responses. |
| Chart `replicas` | `1` | Keep it at 1. Every replica uses the same token, so two replicas with 8 job slots each need 16 open polls on a token the server allows 8; the extra polls are refused. The chart prints this warning after install when `replicas` is above 1. For more capacity, install the chart once per agent, each with its own token, or raise the server limit to replicas times jobs. |
| Chart `resources` | requests 100m CPU and 384Mi, limit 768Mi | Enough for the default concurrency. |

An idle agent costs the server little: in the load test, 200 idle agents each caused about 0.8
database queries a second.

## Revoke a token

On the **Agents** page, open the agent, select **Revoke token** and confirm (or use **Revoke** on
the **Agents** card of the organization page). In the API it is
`DELETE /api/v1/agent-tokens/<id>?organizationId=<id>`. The agent using it gets `401` on its next
call and cannot connect again; the page shows it as **Revoked**. The agent's own keys and secrets stay in
its secret store; delete them there if you retire the agent.

Agent health is reported by a heartbeat every 5 minutes; after two missed heartbeats the server
treats the agent as stale. If an agent seems offline, see
[operations.md](operations.md#troubleshooting).
