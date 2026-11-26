# certping-agent Helm chart

Installs one CertPing agent in a Kubernetes cluster. Use it for targets the
server's bundled agent cannot reach: another cluster, a VPC or a data center.
The agent only connects out, over HTTPS, to your CertPing server. It opens no
inbound port.

## Install

1. In CertPing, open **Agents** and select **Add agent**, then **Create
   token**. Copy the token; it is shown once. The **Kubernetes** tab shows a
   ready `helm install` command for the store you chose.
2. Store the token in a Secret:

   ```bash
   kubectl -n certping-agent create secret generic certping-agent-token \
     --from-literal=token=cpa_...
   ```

3. Install the chart:

   ```bash
   cd deploy/charts/certping-agent
   helm install edge . -n certping-agent \
     --set serverUrl=https://certping.example.com \
     --set secretStore.provider=AZURE_KV \
     --set secretStore.azureKv.vaultUri=https://<vault>.vault.azure.net
   ```

The token decides which organization the agent works for. The agent shows
**Online** on the **Agents** page once it connects. Revoke its token there
(**Revoke token**); the agent stops at its next request.

## Required values

| Value | Purpose |
| --- | --- |
| `serverUrl` | The CertPing URL. |
| `tokenSecret.name`, `tokenSecret.key` | The Secret with the agent token. Default `certping-agent-token`, key `token`. |
| `secretStore.provider` | Where the agent keeps private keys and credentials: `AZURE_KV`, `AWS_SECRETS_MANAGER` or `GCP_SECRET_MANAGER`. |

And the settings for the store you chose:

| Store | Values |
| --- | --- |
| Azure Key Vault | `secretStore.azureKv.vaultUri`, `secretStore.azureKv.authMode` (`WORKLOAD_IDENTITY` or `DEFAULT`) |
| AWS Secrets Manager | `secretStore.awsSecretsManager.region`, `secretStore.awsSecretsManager.authMode` (`DEFAULT`, the default, or `WEB_IDENTITY_TOKEN`, `INSTANCE_PROFILE`, `PROFILE`, `STATIC`) |
| Google Secret Manager | `secretStore.gcpSecretManager.projectId`, `secretStore.gcpSecretManager.authMode` (`ADC`) |

For workload identity, add the annotation for your cloud under
`serviceAccount.annotations` (examples are in `values.yaml`).

On EKS with IAM roles for service accounts, keep `secretStore.awsSecretsManager.authMode=DEFAULT`:
the AWS default chain picks up what EKS injects. `WEB_IDENTITY_TOKEN` also needs the role ARN and
token file, which this chart does not set (use `extraEnv` with
`AGENT_SECRETSTORE_AWSSECRETSMANAGER_ROLEARN` and
`AGENT_SECRETSTORE_AWSSECRETSMANAGER_WEBIDENTITYTOKENFILE`). Full examples for Azure, AWS and GCP:
[docs/agents.md](../../../docs/agents.md#run-on-kubernetes-with-the-certping-agent-chart).

Optional values:

| Value | Default | Purpose |
| --- | --- | --- |
| `image.tag` | the chart's `appVersion` | Keep it equal to the server's version. |
| `acme.directoryUrl`, `acme.accountEmail` | Let's Encrypt production, empty | The ACME CA (`ACME_DIRECTORY_URL`) and the account contact (`ACME_ACCOUNT_EMAIL`). |
| `acme.eab.keyId`, `acme.eab.hmacKeySecret.name`, `acme.eab.hmacKeySecret.key` | empty, empty, `hmacKey` | External account binding for a CA that requires it (ZeroSSL, Google Trust Services, SSL.com): the key id, and the Secret holding the HMAC key. |
| `extraCaCerts.configMap` or `extraCaCerts.secret`, `extraCaCerts.key` | empty, `ca.crt` | A PEM file of extra CA certificates the agent trusts. |
| `httpsProxy` | empty | Proxy for the agent's connection to the CertPing server. Calls to CAs, DNS and cloud APIs do not read it. |
| `extraEnv`, `extraEnvFrom` | empty | Any other agent variable, for example `CERTPING_AGENT_MAX_CONCURRENT_JOBS` (default 8). |
| `replicas` | `1` | Keep it at 1. Every replica uses the same token, and the server allows 8 open polls per token while each replica opens one per job slot (8 by default), so extra polls are refused. The chart prints a warning after install when it is above 1. Install the chart once per agent, each with its own token, for more capacity. |

## Service account token

`serviceAccount.automountServiceAccountToken` is `true`, because the agent
discovers certificates in its own cluster (Secrets, Ingresses, Gateways) and
deploys renewed ones into Kubernetes Secrets through the in-cluster API. Grant
that service account only the RBAC it needs. Set the value to `false` when the
agent works only with resources outside the cluster.

## NetworkPolicy

`networkPolicy.enabled` is `true` by default. The policy admits no inbound
connections; kubelet probes still work. Egress is open, because the agent
calls CertPing, CAs, cloud APIs and the Kubernetes API.

## Upgrade

```bash
helm upgrade edge . -n certping-agent -f your-values.yaml --set image.tag=<version>
```

Upgrade the server first. An agent a version behind keeps working until you
update it, and the token survives the upgrade.
