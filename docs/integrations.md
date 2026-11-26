# Integrations

Everything CertPing connects to, the credential each needs, and how well it is tested.

The **Status** column in the tables below means:

| Status | Meaning |
| --- | --- |
| End to end | The [end-to-end lab](../deploy/e2e-lab/README.md) runs it for real on every run. |
| Tested live | Run by hand against the real service (November 2026), for the auth modes named. Not part of the lab. |
| Beta (mocks) | Tested only against mocked provider APIs. Not yet verified against the live service. |
| Experimental | Behind feature flags. Its interfaces may change. |

In short: ACME DNS-01 (with the CertPing DNS provider and the Pebble test CA), Kubernetes TLS
secrets, Kubernetes discovery and email are tested end to end. Let's Encrypt with Cloudflare DNS,
the AWS, Azure and GCP deployment targets, and SCEP enrollment from Intune with step-ca are tested
live. Everything else that connects to an outside service is beta.

Credentials are added under **Integrations**: tab **DNS Providers** (**Connect DNS provider**),
tab **Deployment Targets** (**Add deployment target**) and tab **Apps** (chat and incident
tools). Each credential is either pasted and stored, or uses the agent's identity or a secret
handle in your own vault ([Credentials](architecture.md#credentials)). The API value is the
`provider` field of `/api/v1/credentials/dns` and `/api/v1/credentials/deployment`.

## Certificate authorities

| CA | How it is configured | Status |
| --- | --- | --- |
| Let's Encrypt, or any ACME CA | `ACME_DIRECTORY_URL` and `ACME_ACCOUNT_EMAIL` on the agent, plus `ACME_EAB_KEY_ID` and `ACME_EAB_HMAC_KEY` for a CA that requires external account binding (ZeroSSL, Google Trust Services, SSL.com). The agent registers one ACME account per organization. Validation is DNS-01 through a DNS provider below, or manual TXT records. Pick **Let's Encrypt** in the issue form whatever the directory is. | End to end against Pebble, with the CertPing DNS provider. Let's Encrypt staging and production: tested live, with Cloudflare DNS. External account binding: unit tests only. |
| DigiCert CertCentral | A CertCentral API key per organization, saved on the [Certificate authorities tab](#the-certificate-authorities-tab) or when DigiCert is chosen in the issue form. The agent's `DIGICERT_API_BASE_URL` sets the endpoint. | Beta (mocks) |
| GlobalSign Atlas (HVCA) | One account configured on the agent: `AGENT_GLOBALSIGN_API_KEY`, `AGENT_GLOBALSIGN_API_SECRET`, `AGENT_GLOBALSIGN_CLIENT_CERT_PEM_BASE64`, `AGENT_GLOBALSIGN_CLIENT_PRIVATE_KEY_PEM_BASE64`, optional `AGENT_GLOBALSIGN_API_BASE_URL`. Without them orders fail with `GLOBALSIGN_CONFIG_MISSING`. | Beta (mocks) |
| EJBCA, Smallstep step-ca | Used for machine identity (SCEP), configured on the agent. One CA backend per agent. See [Connect a CA](#connect-a-ca). | Experimental. step-ca: tested live with a real Intune enrollment and revocation. EJBCA: connected in the lab, no live enrollment. |

Let's Encrypt needs no API key. The agent creates an ACME account key (RSA 2048) the first time
it orders a certificate and keeps it in its own secret store, under
`acme-acct-<organization id>-<hash of the directory URL>`. Staging and production therefore get
separate accounts. The account key never goes to the server, the database or the web app. See
[key custody](architecture.md#key-custody-and-trust).

### The Certificate authorities tab

**Integrations**, tab **Certificate authorities**, shows every CA CertPing can issue from and
where each one is set up: **Configured**, **Not configured** or **Waiting for an agent report**.
It never shows a private key or an API key. The API behind it is
`GET /api/v1/certificate-authorities`.

- **Let's Encrypt** (any ACME CA): per agent, the **CA address** (**Production**, **Staging** or
  **Custom ACME CA**), **Account email**, **Account URL**, **Key type**, **Created**, and
  **Account key**: "Key kept by agent ...". To change the CA or the email, set
  `ACME_DIRECTORY_URL` or `ACME_ACCOUNT_EMAIL` on the agent and restart it (**How to change**).
- **DigiCert**: the CertCentral API keys saved in this organization, by name and dates. **Add
  key** saves a new one (**Name**, **API key**), **Replace key** rotates one in place, and
  **Delete** removes it. Keys are write-only: after you save a key, CertPing shows only its name
  and dates. A key that a certificate still uses cannot be deleted. Adding, replacing and
  deleting need the credential create, rotate and delete permissions. The API is
  `POST /api/v1/credentials/ca`, then `PUT` and `DELETE` on `/api/v1/credentials/ca/<xref>`.
- **GlobalSign**: set on the agent with environment variables (table above). The tab shows, per
  agent, whether it is configured.

The agent values come from each agent's heartbeat, so a new or changed agent shows up a few
seconds after it starts.

Which CAs the issue form lists also depends on per-CA feature flags. A private ACME CA (step-ca,
an internal Boulder or Pebble) works through `ACME_DIRECTORY_URL`; trust its root with
`CERTPING_EXTRA_CA_CERTS` (all-in-one and Compose) or `extraCaCerts` (Helm).

## DNS providers

Used for ACME DNS-01: the agent writes `_acme-challenge` TXT records, checks every authoritative
nameserver, and deletes the records afterwards.

| Provider | API value | Secret fields | Auth | Status |
| --- | --- | --- | --- | --- |
| Cloudflare | `CLOUDFLARE` | `apiToken` | API token with Zone, DNS, Edit and Zone, Zone, Read on the zone; with the optional `zoneId`, DNS Edit alone is enough | Tested live |
| AWS Route 53 | `AWS_ROUTE53` | `accessKeyId`, `secretAccessKey` | Static IAM keys only; the agent's own AWS identity is not used for DNS. The IAM identity needs `route53:ListHostedZonesByName` and `route53:ChangeResourceRecordSets` | Beta (mocks) |
| GoDaddy | `GODADDY` | `apiKey`, `apiSecret` | API key and secret | Beta (mocks) |
| Name.com | `NAMEDOTCOM` | `username`, `apiToken` | API token | Beta (mocks) |
| Hostinger | `HOSTINGER` | `apiToken` | API token | Beta (mocks) |
| Namecheap | `NAMECHEAP` | `apiUser`, `username`, `apiKey` | API key, plus `NAMECHEAP_CLIENT_IP` on the agent set to the allowlisted IP. The agent rewrites the full host record set, as Namecheap's API requires ([apps/agent/README.md](../apps/agent/README.md#namecheap-dns)). | Beta (mocks) |
| CertPing DNS | `CERTPING` | `apiKey` (`cpk_live_...`) | Token for domains on CertPing's hosted nameservers; base URL `CERTPING_DNS_API_URL` | End to end, against a local stand-in of the API |

Azure DNS and Google Cloud DNS are not supported in 0.0.1-beta. With any other DNS host, use manual
issuance (**I'll add a DNS record**), which does not renew automatically.

## Deployment targets

Auth modes come from the agent's adapters; the permissions each identity needs are in
[Deployment target permissions](#deployment-target-permissions).

| Target | API value | Auth modes | Status |
| --- | --- | --- | --- |
| Kubernetes TLS secrets | `KUBERNETES_SECRETS` | `SA_INCLUSTER` (the agent's service account), `SA_TOKEN` (API server, bearer token, CA), `AWS` (EKS), `AZURE` (AKS), `GCP` (GKE) | End to end with `SA_TOKEN` on k3s. `AZURE` (AKS): tested live. `AWS` (EKS) and `GCP` (GKE): beta (mocks) |
| AWS Certificate Manager | `AWS_ACM` | `STATIC_KEYS`, `ASSUME_ROLE`, `INSTANCE_PROFILE` | Tested live with `INSTANCE_PROFILE` (the agent's own identity); `STATIC_KEYS` and `ASSUME_ROLE`: beta (mocks) |
| AWS Application and Network Load Balancer | `AWS_ALB`, `AWS_NLB` | as ACM | Tested live with `INSTANCE_PROFILE` (the agent's own identity); `STATIC_KEYS` and `ASSUME_ROLE`: beta (mocks) |
| AWS API Gateway (REST, HTTP and WebSocket) | `AWS_API_GW_REST`, `AWS_API_GW_HTTP` | as ACM | REST and HTTP: tested live with `INSTANCE_PROFILE` (the agent's own identity); `STATIC_KEYS` and `ASSUME_ROLE`: beta (mocks) |
| AWS CloudFront | `AWS_CLOUDFRONT` | as ACM | Tested live with `INSTANCE_PROFILE` (the agent's own identity); `STATIC_KEYS` and `ASSUME_ROLE`: beta (mocks) |
| Azure Key Vault (import) | `AZURE_KV` | `SERVICE_PRINCIPAL`, `WORKLOAD_IDENTITY` | Tested live with `SERVICE_PRINCIPAL`; `WORKLOAD_IDENTITY`: beta (mocks) |
| Azure Application Gateway | `AZURE_APP_GW` | `SERVICE_PRINCIPAL`, `WORKLOAD_IDENTITY` | Tested live with `SERVICE_PRINCIPAL`; `WORKLOAD_IDENTITY`: beta (mocks) |
| Azure Front Door | `AZURE_AFD` | `SERVICE_PRINCIPAL`, `WORKLOAD_IDENTITY` | Tested live with `SERVICE_PRINCIPAL`; `WORKLOAD_IDENTITY`: beta (mocks) |
| Azure Application Gateway for Containers | `AZURE_APP_GW_CONTAINERS` | `SERVICE_PRINCIPAL`, `WORKLOAD_IDENTITY` | Beta (mocks). Implemented in the agent; not offered in the web form. |
| GCP Certificate Manager | `GCP_CERT_MANAGER` | `SERVICE_ACCOUNT_KEY`, `WORKLOAD_IDENTITY` | Tested live with `SERVICE_ACCOUNT_KEY`; `WORKLOAD_IDENTITY`: beta (mocks) |
| GCP load balancer (target HTTPS proxy) | `GCP_ALB` | as Certificate Manager | Tested live with `SERVICE_ACCOUNT_KEY`: global proxies with and without a certificate map, and a regional proxy; `WORKLOAD_IDENTITY`: beta (mocks) |
| GCP proxy network load balancer | `GCP_PROXY_NLB` | as Certificate Manager | Tested live with `SERVICE_ACCOUNT_KEY`, with and without a certificate map (global proxies only); `WORKLOAD_IDENTITY`: beta (mocks) |
| GCP API Gateway, GCP Cloud CDN | `GCP_API_GW`, `GCP_CLOUD_CDN` | as Certificate Manager | Beta: the same code as `GCP_ALB`, which is tested live, but not run separately. Hidden in the web form because they use the ALB flow. |
| Cloudflare edge (custom certificates) | `CLOUDFLARE_EDGE` | API token | Beta (mocks) |
| Akamai CPS (third-party enrollment) | `AKAMAI_CPS` | EdgeGrid client token, access token and client secret | Beta (mocks) |
| F5 BIG-IP (client SSL profile) | `F5_BIGIP` | iControl REST username and password | Beta (mocks) |

Azure targets need roles beyond the target resource: Key Vault certificate import, the
Application Gateway's subnet and managed identity, and Key Vault read access for the gateway or
Front Door itself. The full list is in
[Azure deployment targets](#4-azure-deployment-targets).

Kubernetes credential fields and how the agent writes secrets:
[Kubernetes secrets](#3-kubernetes-secrets).

## Discovery sources

Discovery is read-only. It is started from **Certificate Discovery** in the sidebar.

| Source | What it reads | Credential | Status |
| --- | --- | --- | --- |
| Kubernetes | TLS secrets and their usage by Ingresses, Gateway API routes, Traefik, Contour, OpenShift routes and workloads | The Kubernetes credential types above, with read RBAC ([Kubernetes discovery](#kubernetes-discovery)) | End to end on k3s |
| AWS Certificate Manager, one account | ACM in the region set on the discovery configuration | The agent's AWS identity with `acm:ListCertificates`, `acm:DescribeCertificate`, `acm:GetCertificate`, `account:ListRegions` | Beta (mocks) |
| AWS Organization | ACM in every account and region of an organization, through a hub role and a member role | CloudFormation templates in [deploy/discovery/aws](../deploy/discovery/aws/README.md) | Beta (mocks) |
| Azure Key Vault | Certificates in one vault | Service principal or workload identity, with `tenantId` and the vault URI | Beta (mocks) |

These four are the only discovery sources. Discovery reads certificate stores; it does not
connect to endpoints to read the certificate they serve, and endpoint probing is on the roadmap.
Discovery of Azure Application Gateway, Azure Front Door, Azure tenant-wide and Google Cloud is
not supported, and the server refuses such a request. These services are still deployment targets
above.

A scan that fails for part of its scope, such as one account or region, ends with status `PARTIAL`
and lists the failed scopes. Certificates in those scopes keep their last known state and are not
marked missing. What a discovered certificate records (the `managed` flag, inventory status) is in
[Discovery](architecture.md#discovery).

Kubernetes discovery across all namespaces needs cluster-wide read on TLS secrets, which lets the
agent read every TLS private key in the cluster. Scope it to the namespaces you need
([Kubernetes namespace scope](architecture.md#kubernetes-scope-to-the-namespaces-you-need)).

## Notification channels

| Channel | Sent by | Configured in | Status |
| --- | --- | --- | --- |
| Email | Notifier, through your SMTP server | `MAIL_*` settings ([configuration.md](configuration.md#email-notifier)) | End to end, with Mailpit |
| Slack | Server, incoming webhook | **Integrations**, tab **Apps** | Beta (mocks) |
| Microsoft Teams | Server, incoming webhook | **Integrations**, tab **Apps** | Beta (mocks) |
| PagerDuty | Server, Events API (`INCIDENTS_PAGERDUTY_BASE_URL`, default `https://events.pagerduty.com`) | **Integrations**, tab **Apps** | Beta (mocks) |
| ServiceNow ITSM | Server, creates incidents | **Integrations**, tab **Apps** | Beta (mocks) |

Webhook URLs, the ServiceNow password and the PagerDuty routing key are kept in the server's
secret store ([configuration.md](configuration.md#secret-store-server)), never in the database.
Webhook and ServiceNow URLs that resolve to private addresses are refused unless
`INTEGRATIONS_ALLOW_PRIVATE_ADDRESSES=true`.

## Agent secret stores

| Store | Value | Status |
| --- | --- | --- |
| Local encrypted files | `LOCAL` | End to end (the all-in-one in the lab) |
| Azure Key Vault | `AZURE_KV` | Beta (mocks) |
| AWS Secrets Manager | `AWS_SECRETS_MANAGER` | Beta (mocks) |
| Google Secret Manager | `GCP_SECRET_MANAGER` | Beta (mocks) |

Settings and identity examples: [agents.md](agents.md#choose-a-secret-store).

## Other features

These are not integrations, but their test status is listed here so all of it is in one place.

| Feature | Status |
| --- | --- |
| Scheduled renewal and redeployment | End to end |
| First admin sign-in, forced password change, `certping-admin` password recovery | End to end |
| Audit log with export, local sign-in with TOTP, one OpenID Connect provider | Unit and integration tests; also tested by hand from the UI in the lab (November 2026), with Dex as the OpenID Connect provider |
| PQC readiness report and CycloneDX CBOM export. It classifies algorithms; it does not issue post-quantum certificates | Unit tests; also tested by hand from the UI in the lab (November 2026) |

## Machine identity (experimental)

A SCEP endpoint in the agent, device sources such as Microsoft Intune, device certificate
inventory and certificate profiles. It is off by default (`SCEP_ENABLED=false`) and its pages are
behind feature flags. Setup, permissions and limits:
[Machine identity](#machine-identity-experimental).

## How agent errors are classified

Every failure the agent reports is permanent, retryable or transient, and carries a code such as
`DNS_PROPAGATION_TIMEOUT`. See [architecture.md](architecture.md#the-job-queue) and the
troubleshooting table in [operations.md](operations.md#troubleshooting).

## Deployment target permissions

The authentication, authorization and network access each deployment target needs, as the agent
implements it. Provider permissions and built-in role names change, so check them against the
provider's documentation before a production rollout. The list of targets and their test status
is in [Deployment targets](#deployment-targets).

### 1. Two identities are usually involved

1. The agent's own identity reads the deployment credential and the certificate's private key
   from the agent's secret store (`LOCAL`, Azure Key Vault, AWS Secrets Manager or Google Secret
   Manager; see [agents.md](agents.md#choose-a-secret-store)).
2. The target identity, either that stored credential or the agent's workload identity,
   signs in to the target.

Do not give the target identity access to every credential secret. Likewise, permission to read
secrets does not grant permission to update a cluster, load balancer or CDN.

When the secret store is a cloud vault, the agent's identity needs read access to the secrets it
uses (for example Key Vault Secrets User with Azure RBAC), plus network access and private DNS
when the vault uses a private endpoint.

### 2. Authentication modes

| Provider | Supported authentication modes | Long-lived secret required? |
| --- | --- | --- |
| Azure targets | `SERVICE_PRINCIPAL`, `WORKLOAD_IDENTITY` | A service principal needs `clientId` and `clientSecret`; workload identity does not |
| AWS targets | `STATIC_KEYS`, `ASSUME_ROLE`, `INSTANCE_PROFILE` | Static keys need a key pair. `ASSUME_ROLE` can start from the agent's own identity, and `INSTANCE_PROFILE` always does |
| GCP targets | `SERVICE_ACCOUNT_KEY`, `WORKLOAD_IDENTITY` | `SERVICE_ACCOUNT_KEY` needs a JSON key; workload identity uses application default credentials |
| Kubernetes | `SA_INCLUSTER`, `SA_TOKEN`, `AWS`, `AZURE`, `GCP` | Depends on the mode ([credential fields](#credential-fields)) |
| Cloudflare | API token | Yes |
| Akamai CPS | EdgeGrid credentials | Yes |
| F5 BIG-IP | iControl REST username and password | Yes |

Workload identity only replaces a stored credential. It grants no permission on the target and
no network path to it.

### 3. Kubernetes secrets

Target type: `KUBERNETES_SECRETS`

The Kubernetes identity needs these RBAC permissions in every target namespace:

```yaml
apiGroups: [""]
resources: ["secrets"]
verbs: ["get", "create", "update", "delete"]
```

The agent writes a staged secret first and removes it afterwards (see below), so `delete` is
required. When the target deploys to all namespaces, also grant cluster-scoped:

```yaml
apiGroups: [""]
resources: ["namespaces"]
verbs: ["list"]
```

Prefer namespace-scoped `Role` and `RoleBinding` objects. Use a `ClusterRole` only when the target
deploys to all namespaces or a cluster-wide deployment is deliberate.

Deploying to all namespaces writes the private key into every namespace of the cluster, including
`kube-system`. List the namespaces you need instead. The agent also replaces an existing Secret of
the same name, even one that cert-manager or another tool manages, so do not target such a Secret
([Kubernetes namespace scope](architecture.md#kubernetes-scope-to-the-namespaces-you-need)).

#### `SA_INCLUSTER`

The agent uses its own Kubernetes service account. Bind that service account to the
namespace-scoped role above. No cloud identity is involved.

#### `SA_TOKEN`

The identity behind the bearer token needs the same RBAC permissions, and the agent must be able
to reach the API server URL in the credential.

The [getting started tutorial](getting-started.md#5-give-certping-a-kubernetes-identity)
creates such a service account and token. To register the cluster with the API instead of the web
form, which is what the end-to-end lab does (you need `curl` and `jq`):

```sh
CERTPING=http://localhost
read -rs -p "CertPing admin password: " PW; echo
TOKEN=$(jq -n --arg pw "$PW" '{identifier: "admin", password: $pw}' \
  | curl -fsS -H 'Content-Type: application/json' -d @- "$CERTPING/api/auth/login" | jq -r .token)

API_SERVER=https://my-cluster.example.com:6443   # must be reachable from the agent
SA_TOKEN=$(kubectl -n app get secret certping-token -o jsonpath='{.data.token}' | base64 -d)
CA_PEM=$(kubectl -n app get secret certping-token -o jsonpath='{.data.ca\.crt}' | base64 -d)

jq -n --arg api "$API_SERVER" --arg tok "$SA_TOKEN" --arg ca "$CA_PEM" '{
  provider: "KUBERNETES_SECRETS",
  description: "my-cluster",
  configJson: {authMethod: "SA_TOKEN", clusterName: "my-cluster", namespaces: ["app"]},
  credJson: {apiServer: $api, bearerToken: $tok, caCertPem: $ca}
}' | curl -fsS -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d @- "$CERTPING/api/v1/credentials/deployment"
```

#### AKS (`AZURE`)

The Azure identity needs:

- Permission to read the AKS cluster.
- Permission to obtain AKS user credentials. The corresponding ARM action is
  `Microsoft.ContainerService/managedClusters/listClusterUserCredential/action`.
- Kubernetes authorization to write secrets after login.

The built-in Azure Kubernetes Service Cluster User Role on the cluster grants the read and the
user credentials. It does not grant permission to write Kubernetes secrets.

The agent signs in to the API server with a Microsoft Entra ID token, so the cluster must use
Microsoft Entra ID integration. If it uses Azure RBAC for Kubernetes Authorization, grant Azure
Kubernetes Service RBAC Writer (or a custom role that allows secret operations) scoped to each
target namespace, `<cluster id>/namespaces/<namespace>`. If it uses Kubernetes RBAC, create a
`Role` and a `RoleBinding` for the identity's object ID in each target namespace.

The cluster API server must be reachable from the agent. Sign-in to Azure goes through ARM and
succeeds for a private cluster, but the secret writes then fail; see
[Private clusters](#private-clusters).

The credential has two forms:

- Service principal: `azureTenantId`, `azureSubscriptionId`, `azureResourceGroup`,
  `azureClientId`, and `azureClientSecret`.
- Workload identity: the same routing fields and `azureClientId`, without a client secret. The agent
  pod must receive a federated token trusted by the app registration.

#### EKS (`AWS`)

The AWS identity needs:

- `eks:DescribeCluster`.
- `sts:AssumeRole` when `awsRoleArn` is used.
- An EKS access entry or legacy `aws-auth` mapping that maps the IAM identity into Kubernetes.
- Kubernetes RBAC for secret writes.

The assumed role's trust policy must trust the bootstrap identity. For IRSA, it must trust the
cluster's OIDC provider and the exact Kubernetes ServiceAccount subject.

#### GKE (`GCP`)

The Google identity needs:

- Permission equivalent to `container.clusters.get`.
- Permission to authenticate to the cluster.
- Kubernetes RBAC for secret writes.

Use a custom role or a GKE role that covers these, then bind the Google identity to the Kubernetes
RBAC permissions above.

#### Private clusters

With a private AKS, EKS, GKE or other cluster, sign-in to the cloud can succeed while the secret
writes fail. The agent needs a route, a firewall opening and DNS resolution for the private API
endpoint, over HTTPS.

#### Credential fields

The Kubernetes credential names the cluster (`clusterName`), the auth mode and the namespaces it
may write to (a list, or all namespaces). Its secret part depends on the mode:

| Mode | Required fields | Optional fields | How the agent signs in |
| --- | --- | --- | --- |
| `SA_INCLUSTER` | none | none | The agent pod's own service account |
| `SA_TOKEN` | `apiServer`, `bearerToken` (or `serviceAccountToken`), `caCertPem` (or `caCertBase64`) | none | The token, straight to the API server |
| `AWS` (EKS) | `awsRegion`, and either `awsAccessKeyId` with `awsSecretAccessKey` or `awsRoleArn` | `awsRoleArn` with static keys | Static keys first; otherwise the agent's workload identity (for example IRSA) assumes `awsRoleArn`. `DescribeCluster`, then a short-lived EKS token |
| `AZURE` (AKS) | `azureTenantId`, `azureSubscriptionId`, `azureResourceGroup`, `azureClientId` | `azureClientSecret` | Client secret if present, otherwise Azure workload identity (`AZURE_FEDERATED_TOKEN_FILE` must be set in the pod). Fetches the AKS user kubeconfig, held in memory only |
| `GCP` (GKE) | `gcpProjectId`, `gcpLocation` | `gcpServiceAccountJson` or `gcpServiceAccountJsonBase64` | Service account JSON if present, otherwise application default credentials (GKE workload identity) |

With `AWS`, `AZURE` and `GCP` the credential is still needed even with workload identity, because
it carries the region, subscription or project that locates the cluster. With no static keys and
no `awsRoleArn`, deployment fails at once with a configuration error.

#### How the agent writes the secrets

Each deployment of a certificate to a cluster maps namespaces to secret names. Namespaces must be
inside the credential's allowed list; names must be valid Kubernetes names (namespace: lowercase
DNS label up to 63 characters; secret: lowercase DNS subdomain up to 253 characters, no
underscores). A Kubernetes target added to a certificate without a namespace mapping fails with
`DEPLOYMENT_CONFIG_MISSING`.

1. Preflight: a server-side dry run of every staged and final write, in every target
   namespace, before anything is written. RBAC, quota and admission problems fail here.
2. Stage: a staged copy of the secret is written in every namespace.
3. Promote: only when every namespace is staged, the agent writes the final secret
   (`kubernetes.io/tls` with `tls.crt` and `tls.key`) in each namespace, updating it in place when
   it exists.
4. Clean up: staged secrets are deleted, after success or failure. A cleanup failure is logged
   and does not change the result.

This is not a transaction across namespaces: a failure during the promote step can leave some
namespaces on the new certificate and others on the old one. Short-lived tokens are refreshed
once on a `401` or `403` during a run. Kubernetes API errors reach the server as a stable code and
a `debugId`; the detail is in the agent log, with secret values redacted.

### 4. Azure deployment targets

Azure targets accept a service principal or workload identity. The permissions below are the same
for both. With workload identity the credential must carry the Client ID of the federated app
registration or managed identity; without it the deployment fails at once with a message naming
the missing Client ID.

Two identities are involved in most Azure targets:

- The deployment identity: the service principal or workload identity in the CertPing
  credential, used by the agent.
- The service's own identity: Application Gateway or Front Door, which reads the certificate
  from Key Vault when it serves it.

When the deployment identity lacks a role, Azure names the denied action and resource. The agent
logs that message and the deployment fails with "An Azure identity used by this deployment is
missing a permission it needs". This includes Azure errors returned as HTTP 409, such as
`ApplicationGatewayInsufficientPermissionOnSubnet`, which are not resource conflicts.

#### Key Vault import (all three Key Vault targets)

`AZURE_KV`, `AZURE_APP_GW` and `AZURE_AFD` each import a certificate into a Key Vault. The
deployment identity needs certificate import on that vault:

- Azure RBAC vaults: Key Vault Certificates Officer on the vault (data action
  `Microsoft.KeyVault/vaults/certificates/import/action`).
- Access policy vaults: the certificate `Import` permission.

The vault's firewall must also let the agent in.

#### `AZURE_KV`

The agent imports the certificate, as PEM, into the target vault under the configured certificate
name. Each renewal adds a new version of that certificate. It needs only the Key Vault import
permission above.

#### `AZURE_APP_GW`

The agent imports the certificate, as PKCS#12, into the configured Key Vault, reads the
Application Gateway, adds or updates the SSL certificate that points at the new Key Vault secret
version, and sets it on the selected listeners. The update is a PUT of the whole gateway, so Azure
checks the deployment identity's access to every resource the gateway references, not only the
gateway itself.

The deployment identity needs:

| Scope | Permission | Built-in role |
| --- | --- | --- |
| The Key Vault | Certificate import | Key Vault Certificates Officer |
| The Application Gateway | `Microsoft.Network/applicationGateways/read` and `.../write` | Network Contributor, or a custom role |
| The gateway's subnet | `Microsoft.Network/virtualNetworks/subnets/join/action` | Network Contributor on the subnet |
| The gateway's user-assigned managed identity | `Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action` | Managed Identity Operator |

Without the subnet permission Azure answers HTTP 409
`ApplicationGatewayInsufficientPermissionOnSubnet`. Without the identity permission it answers
`LinkedAuthorizationFailed`. Other resources the gateway references, such as a public IP address
or a WAF policy, can need their own `join/action` in the same way. Network Contributor on the
gateway's resource group covers all of the network actions.

The gateway's own user-assigned managed identity must be able to read the certificate secret:
Key Vault Secrets User on the vault (RBAC), or the secret `Get` permission (access policy).

#### `AZURE_AFD`

The agent imports the certificate, as PKCS#12, into Key Vault, creates or replaces the Front Door
secret resource that points at the Key Vault secret with "latest version", and sets that secret on
the TLS settings of the selected custom domains. It finds each custom domain by host name, so the
domain must already exist on the profile.

The deployment identity needs:

| Scope | Permission | Built-in role |
| --- | --- | --- |
| The Key Vault | Certificate import | Key Vault Certificates Officer |
| The Front Door profile | Read and write on `Microsoft.Cdn/profiles/secrets` and `Microsoft.Cdn/profiles/customDomains` | CDN Profile Contributor |

Front Door itself must be able to read the Key Vault secret. Grant Key Vault Secrets User on the
vault (or the secret `Get` permission with access policies) to the profile's managed identity, or,
when the profile uses no managed identity, to the Microsoft.AzureFrontDoor-Cdn service principal
(application ID `205478c0-bd83-4e1b-a9d6-db63a3e1e1c8`).

#### Key Vault certificate names

Give each target its own Key Vault certificate name. In particular, an `AZURE_KV` target and an
`AZURE_AFD` target must not use the same certificate name in the same vault. Front Door always
serves the latest version of the secret, and an `AZURE_KV` deployment adds a PEM version that
Front Door rejects, so Front Door stops picking up the certificate.

#### `AZURE_APP_GW_CONTAINERS`

This target writes the Kubernetes TLS secrets that Application Gateway for Containers reads. With
`SA_INCLUSTER` it needs only Kubernetes RBAC. With Azure sign-in the deployment identity needs:

- Azure Kubernetes Service Cluster User Role on the AKS cluster.
- Azure Kubernetes Service RBAC Writer scoped to each target namespace on clusters with Azure
  RBAC for Kubernetes Authorization, or a Kubernetes `Role` and `RoleBinding` on clusters with
  Kubernetes RBAC.

The cluster API server must be reachable from the agent, so a private cluster needs an agent
inside its network. Details are in [AKS](#aks-azure).

### 5. AWS deployment targets

With `ASSUME_ROLE`, the starting identity needs `sts:AssumeRole`, and the target role's trust policy
must trust that identity. The permissions below belong on the identity that ends up calling AWS:
the assumed role, or the static keys or instance profile.

#### ACM permissions for every AWS target

All AWS targets import certificates into ACM. Grant:

```text
acm:ImportCertificate
```

Some targets also clean up an old certificate:

```text
acm:DeleteCertificate
```

Scope permissions to the intended region and certificate resources where AWS supports it.

#### `AWS_ACM`

- `acm:ImportCertificate`

#### `AWS_ALB` and `AWS_NLB`

The agent imports into ACM and replaces the certificate on the configured listeners:

```text
acm:ImportCertificate
elasticloadbalancing:AddListenerCertificates
elasticloadbalancing:RemoveListenerCertificates
```

#### `AWS_API_GW_REST`

The agent reads the custom domain's endpoint type, imports into ACM and updates the custom domain:

```text
acm:ImportCertificate
apigateway:GET
apigateway:PATCH
```

Restrict API Gateway resources to the allowed custom-domain names.

#### `AWS_API_GW_HTTP`

The agent imports into ACM and updates the API Gateway v2 custom domain:

```text
acm:ImportCertificate
apigateway:PATCH
```

#### `AWS_CLOUDFRONT`

CloudFront only uses ACM certificates in `us-east-1`. The agent needs:

```text
acm:ImportCertificate
acm:DeleteCertificate
cloudfront:GetDistribution
cloudfront:GetDistributionConfig
cloudfront:UpdateDistribution
```

Scope CloudFront permissions to the configured distribution.

### 6. GCP deployment targets

For `WORKLOAD_IDENTITY`, the runtime identity must be bound to the target Google service account or
granted permissions directly. When `impersonateServiceAccount` is configured, the source identity
also needs `iam.serviceAccounts.getAccessToken`, normally granted through
Service Account Token Creator, on that service account.

#### `GCP_CERT_MANAGER`

The agent creates, updates and deletes Certificate Manager certificates, and lists, creates and
updates certificate map entries when a certificate map is configured. Certificate Manager Editor
covers this; a custom role with only those certificate and map entry operations is narrower.

#### `GCP_ALB`, `GCP_API_GW`, and `GCP_CLOUD_CDN`

These three share one implementation. The agent creates and deletes Compute SSL certificates, not
Certificate Manager certificates, and reads and updates the configured target HTTPS proxy. For a
regional proxy it creates the certificate in the proxy's region. Use a custom role in the target
project; the built-in Compute roles grant far more than this. For a global proxy:

```text
compute.sslCertificates.create
compute.sslCertificates.get
compute.sslCertificates.delete
compute.targetHttpsProxies.get
compute.targetHttpsProxies.setSslCertificates
compute.globalOperations.get
```

For a regional proxy:

```text
compute.regionSslCertificates.create
compute.regionSslCertificates.get
compute.regionSslCertificates.delete
compute.regionTargetHttpsProxies.get
compute.regionTargetHttpsProxies.setSslCertificates
compute.regionOperations.get
```

##### Proxies with a certificate map

Google Cloud ignores a proxy's own certificates while a certificate map is attached to it. When the
agent finds a map on a global target HTTPS proxy or target SSL proxy, it deploys into that map
instead: it uploads the certificate to Certificate Manager in the map's project and location, points
the map entry for each of the certificate's hostnames at it (creating entries that are missing), and
deletes the certificate it replaced. A renewal with the same hostnames updates the certificate in
place. On top of the proxy's `get` permission above, this needs Certificate Manager Editor in the
map's project, or a custom role with:

```text
certificatemanager.certs.create
certificatemanager.certs.get
certificatemanager.certs.update
certificatemanager.certs.delete
certificatemanager.certs.use
certificatemanager.certmapentries.list
certificatemanager.certmapentries.get
certificatemanager.certmapentries.create
certificatemanager.certmapentries.update
certificatemanager.operations.get
```

#### `GCP_PROXY_NLB`

The agent creates and deletes Compute SSL certificates and reads and updates the configured target
SSL proxy. Only global target SSL proxies are supported, so set `location` to `global`. Use a custom
role in the target project with:

```text
compute.sslCertificates.create
compute.sslCertificates.get
compute.sslCertificates.delete
compute.targetSslProxies.get
compute.targetSslProxies.setSslCertificates
compute.globalOperations.get
```

A target SSL proxy with a certificate map attached is deployed through the map, with the
Certificate Manager permissions listed under
[proxies with a certificate map](#proxies-with-a-certificate-map).

### 7. Cloudflare edge

Target type: `CLOUDFLARE_EDGE`

Use a Cloudflare API token limited to the accounts and zones in the credential's scope, with Zone
read and SSL and Certificates edit. The edit permission is what uploads and activates custom
certificates. Do not use the global API key.

### 8. Akamai CPS

Target type: `AKAMAI_CPS`

The credential contains EdgeGrid `clientToken`, `accessToken`, and `clientSecret`.

The Akamai API client must be authorized for the configured CPS enrollments and contracts. It needs
to read enrollment and change state, and to deploy and activate certificate changes on the selected
network. Limit the API client to those CPS resources.

### 9. F5 BIG-IP

Target type: `F5_BIGIP`

The BIG-IP user authenticates through iControl REST. It needs permission within the allowed
partitions to:

- Upload files.
- Install and read SSL certificates and keys.
- Read and update client SSL profiles.
- Read and update the device group configuration, when synchronization is on.

Use a dedicated BIG-IP account with partition-level restrictions. The agent must also have network
access to the BIG-IP management endpoint.

### 10. Least-privilege checklist

- Give the agent runtime identity read access only to the secrets it needs.
- Prefer workload identity, `ASSUME_ROLE` or service account federation over long-lived secrets.
- Scope roles to the exact subscriptions, resource groups, projects, regions, accounts,
  distributions, listeners, zones, partitions and Kubernetes namespaces.
- Separate deployment identities by customer and target type.
- Treat provider authorization and Kubernetes RBAC as separate requirements.
- For private endpoints, set up routing, firewall rules and private DNS before testing IAM.
- Validate access with a non-production target before granting broader permissions.
- Review role assignments regularly and remove unused credentials and trust relationships.

## Kubernetes discovery

Kubernetes discovery reads the TLS certificates stored in a cluster and records where each one is
used. It answers the question: "if this certificate expires, what breaks?" It is read-only. It
uses the same Kubernetes credential types as deployment
([Credential fields](#credential-fields)) with read RBAC instead of
write RBAC.

### Scope

A scan covers either a list of namespaces or all namespaces, as set on the credential.

- A list of namespaces scans exactly those namespaces and needs read access only there.
  Duplicates are removed. A blank or invalid name fails the scan.
- All namespaces first lists namespaces, which needs cluster-wide `list` on `namespaces`. If
  that is denied the scan fails with `DISCOVERY_K8S_NAMESPACE_LIST_DENIED`.

All namespaces needs cluster-wide read on TLS Secrets, which lets the agent's identity read every
TLS private key in the cluster. Scope the credential to the namespaces you need
([Kubernetes namespace scope](architecture.md#kubernetes-scope-to-the-namespaces-you-need)).

### What is found

Certificate sources:

- `Secret` objects of type `kubernetes.io/tls` that have `tls.crt`.
- Inline certificates in OpenShift `Route` objects (`spec.tls.certificate`).

Where each certificate is used:

- Ingress `spec.tls[].secretName`. When a TLS entry lists hosts, only the matching rule backends
  count; without hosts, all backends of the Ingress count.
- Gateway API `Gateway` listener `tls.certificateRefs[]`, and the `HTTPRoute`, `TLSRoute` and
  `TCPRoute` backends attached to that Gateway, including cross-namespace parents.
- Traefik `IngressRoute`, `IngressRouteTCP` and `TraefikService` (weighted, mirroring and failover
  services are followed, with cycle protection), Istio `Gateway`, Contour `HTTPProxy` (including
  delegated `namespace/secret` references) and OpenShift `Route`.
- Services to Pods through selectors, and Pods to their owning Deployment, StatefulSet,
  DaemonSet, Job or CronJob.
- Workloads that mount the secret: secret and projected volumes, `env.valueFrom.secretKeyRef` and
  `envFrom.secretRef`, including init containers and standalone Pods.

Custom resources are read only for the versions below, whose fields are tested. There is no
guessing by field name.

| Integration | API group | Version | Kinds |
| --- | --- | --- | --- |
| Gateway API | `gateway.networking.k8s.io` | `v1` | `Gateway`, `HTTPRoute`, `TLSRoute`, `TCPRoute` |
| Traefik | `traefik.io` | `v1alpha1` | `IngressRoute`, `IngressRouteTCP`, `TraefikService` |
| Traefik (legacy group) | `traefik.containo.us` | `v1alpha1` | `IngressRoute`, `TraefikService` |
| Istio | `networking.istio.io` | `v1beta1` | `Gateway` |
| Contour | `projectcontour.io` | `v1` | `HTTPProxy` |
| OpenShift | `route.openshift.io` | `v1` | `Route` |

If an installed resource is served only in another version, discovery does not skip it silently:
it marks the result incomplete and warns with the supported version. To see what your cluster
serves:

```bash
kubectl get crd -o custom-columns='NAME:.metadata.name,SERVED:.spec.versions[?(@.served==true)].name'
kubectl api-resources --api-group=route.openshift.io
```

### Complete and incomplete results

Each Kubernetes result carries:

- `usageComplete`: every usage resource type in scope could be read.
- `impactComplete`: impact (hostnames, services, workloads) was computed from complete usage and
  every backend was inside the scanned namespaces.
- `unreadableResourceTypes`: the kinds that could not be listed, for example `Ingress`.

An empty usage list means "unused" **only** when `usageComplete` is true. Otherwise it means "no
usage found in what could be read". A Gateway in `gateway-system` that points to a Service in
`frontend`, when only `gateway-system` was scanned, is reported with `impactComplete` false.

Failure to list Secrets in a namespace fails the scan, because the inventory would not be
trustworthy. Failure to list a usage resource only marks the result incomplete.

### RBAC

Read access in each scanned namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: certping-discovery
  namespace: frontend
rules:
  - apiGroups: [""]
    resources: ["secrets", "services", "pods"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs: ["get", "list"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list"]
```

For all namespaces, add:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: certping-discovery-cluster
rules:
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["list"]
```

Add custom resource permissions only for the controllers you run:

```yaml
rules:
  - apiGroups: ["apiextensions.k8s.io"]
    resources: ["customresourcedefinitions"]
    verbs: ["get", "list"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways", "httproutes", "tlsroutes", "tcproutes"]
    verbs: ["get", "list"]
  - apiGroups: ["traefik.io", "traefik.containo.us"]
    resources: ["ingressroutes", "ingressroutetcps", "traefikservices"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.istio.io"]
    resources: ["gateways"]
    verbs: ["get", "list"]
  - apiGroups: ["projectcontour.io"]
    resources: ["httpproxies"]
    verbs: ["get", "list"]
  - apiGroups: ["route.openshift.io"]
    resources: ["routes"]
    verbs: ["get", "list"]
```

Reading `customresourcedefinitions` lets discovery tell "not installed" from "not allowed". Without
it, a `403` on a custom resource is checked against API discovery: a resource type the API server
does not serve is skipped, and one it serves marks the result incomplete with a warning naming the
missing `list` permission. This matters on k3s and k3d, which
can install both Traefik API groups.

### Security

Read access to Secrets exposes private keys at the Kubernetes API level, even though discovery
never reads, logs or returns `tls.key`. Results never contain PEM, private keys, tokens,
kubeconfigs or cloud credentials. Certificate data is limited to 1 MiB per input and 20
certificates per bundle; anything invalid or larger is skipped with a warning.

### Troubleshooting from the agent log

The log names the namespace, the resource type, the HTTP status and the RBAC rule that is missing,
without response bodies or secret data.

```text
Kubernetes certificate source inventory failed namespace=dev resourceType=Secret statusCode=403 requiredRbac="list secrets in namespace dev"
```

The scan failed: grant `list` on `secrets` in `dev` and run it again (`DISCOVERY_K8S_SECRET_LIST_FAILED`).

```text
Kubernetes usage inventory is incomplete namespace=frontend resourceType=Pod statusCode=403 requiredRbac="list Pod resources in namespace frontend"
```

Certificates were returned, with `usageComplete` false.

```text
Kubernetes custom resource version unsupported resource=ingressroutes.traefik.io supportedVersion=v1alpha1 servedVersions=[v1]
```

The resource is installed in a version this agent does not read; the result is marked incomplete.

The end-to-end lab ([deploy/e2e-lab](../deploy/e2e-lab/README.md)) runs discovery against k3s
on every run.

## Machine identity (experimental)

Device certificates for managed endpoints: CertPing reads the device inventory from Microsoft
Intune, manages Intune SCEP certificate profiles, and runs a SCEP endpoint in the agent that has
device certificates signed by your own EJBCA or Smallstep step-ca. It is off by default, its pages
are behind feature flags, and its interfaces may change.

Everything that touches Intune or your CA happens in the agent, inside your network. The server
never receives Intune credentials, tenant IDs, client secrets or SCEP challenges; it stores only a
non-secret source reference and what the agent reports.

### Turn it on

1. Enable the feature flags for the organization: `IOT_DEVICE_MANAGEMENT` (devices, sources,
   sync), `IOT_PROVIDER_INTUNE` (Intune) and `IOT_CERTIFICATE_PROFILE_MANAGEMENT` (profiles). CA
   health pages use `CA_EJBCA` and `CA_SMALLSTEP`.
2. Configure one or more Intune device sources on the agent (below).
3. Connect a CA (EJBCA or Smallstep) on the agent.
4. Enable the SCEP endpoint on the agent and make it reachable over HTTPS from managed devices.

Every role can view devices, sources, profiles and CA health. Security Analysts can also start
profile discovery, and Organization Admins and Platform Super Admins can also manage sources,
devices and profiles. The permissions are named `iot_device:*`, `iot_source:*`,
`iot_certificate_profile:*` and `iot_ca_health:view`.

### Device sources (Intune)

Sources are agent configuration, one indexed profile each. With environment variables, profile
`0` uses the prefix `AGENT_DEVICE_SOURCES_PROFILES_0_`, profile `1` uses
`AGENT_DEVICE_SOURCES_PROFILES_1_`, and so on.

| Suffix | Required | Example | Meaning |
| --- | --- | --- | --- |
| `PROFILE_REF` | yes | `intune-primary` | Stable source name. Unique across every agent of the organization. Also the SCEP route `/scep/v1/<profile-ref>`. |
| `PROVIDER` | yes | `INTUNE` | The only provider implemented. |
| `DISPLAY_NAME` | yes | `Intune Production` | Shown in the web app. |
| `CREDENTIALS_JSON` | yes | `{"tenantId":"...","clientId":"...","clientSecret":"..."}` | Exactly these three fields. Inject it from your secret manager. |
| `DESCRIPTION` | no | `Corporate Windows devices` | Shown in the web app. No credentials or personal data. |
| `METADATA_ENVIRONMENT`, `METADATA_TENANT_LABEL`, `METADATA_ORGANIZATION_LABEL`, `METADATA_REGION` | no | `production`, `Europe production` | Labels that tell several sources apart. Do not put a tenant GUID here. |

```yaml
env:
  AGENT_DEVICE_SOURCES_PROFILES_0_PROFILE_REF: intune-primary
  AGENT_DEVICE_SOURCES_PROFILES_0_PROVIDER: INTUNE
  AGENT_DEVICE_SOURCES_PROFILES_0_DISPLAY_NAME: Intune Production
  AGENT_DEVICE_SOURCES_PROFILES_0_CREDENTIALS_JSON: '{"tenantId":"...","clientId":"...","clientSecret":"..."}'
```

Only public-cloud Intune (`graph.microsoft.com`) works; other API hosts and clouds are refused.
The agent checks the credentials at startup and reports errors without printing them. Changing a
credential needs an agent restart. Health is checked every 5 minutes
(`AGENT_DEVICE_SOURCES_HEALTH_INTERVAL`).

The app registration needs these Microsoft Graph application permissions, each with tenant admin
consent:

| Permission | Used for | Missing means |
| --- | --- | --- |
| `DeviceManagementManagedDevices.Read.All` | Device inventory and health | Source unhealthy |
| `Device.Read.All` | Entra device details | Source unhealthy |
| `DeviceManagementConfiguration.ReadWrite.All` | Reading and writing certificate profiles | Source degraded |
| `DeviceManagementManagedDevices.PrivilegedOperations.All` | "Check in now" (Graph `syncDevice`) | Source degraded |
| `Application.Read.All` | Finding Intune's SCEP validation service | Every SCEP enrollment fails |

For SCEP it also needs the **Microsoft Intune API** application permission `scep_challenge_provider`
(API permissions, Add a permission, APIs my organization uses, "Microsoft Intune API"), with admin
consent. The agent uses it to check each device's challenge and report the result to Intune.

CertPing keeps the device identifiers needed to match certificates (serial number, Intune and Entra
IDs, IMEI, MEID, Wi-Fi MAC) and operational facts such as compliance and encryption. No user ID,
UPN, email address or owner name is requested or stored.

Starting a sync from the web app runs a full inventory now and then hourly. Stopping it
stops future runs only. A run that fails part way keeps the devices it already received and marks
none as missing; the next run starts over. Decommission changes the device's state in
CertPing only; it never retires or wipes the device in Intune. Check in now asks Intune to
contact the device; the device still decides whether its certificate is due for renewal.

### Connect a CA

The agent signs SCEP requests with one CA backend, chosen with `SCEP_CA_BACKEND` (`ejbca`, the
default, or `smallstep`). One agent serves one backend; to use EJBCA for some devices and
Smallstep for others, run two agents with separate SCEP URLs and point each Intune profile at its
own.

#### EJBCA

EJBCA's REST API must be enabled (it is off on a fresh install:
`ejbca.sh config protocols enable --name "REST Certificate Management"`). Tested with EJBCA
Community 9.3.7.

| Variable | Required | Meaning |
| --- | --- | --- |
| `AGENT_EJBCA_ENABLED` | yes | `true` |
| `AGENT_EJBCA_CREDENTIAL_PATH` or `AGENT_EJBCA_CREDENTIALS_JSON` | one of them | A secret-store handle to the credential JSON, or the JSON itself |
| `AGENT_EJBCA_CA_NAME`, `AGENT_EJBCA_CERTIFICATE_PROFILE_NAME`, `AGENT_EJBCA_END_ENTITY_PROFILE_NAME` | yes | Names from your EJBCA. There are no safe defaults |
| `AGENT_EJBCA_BASE_URL` | no | Overrides `baseUrl` in the credential |
| `AGENT_EJBCA_END_ENTITY_NAME_PREFIX` | no | Prefix for end entity names when device names are not unique |
| `AGENT_EJBCA_REQUEST_TIMEOUT_SECONDS` | no | Default 30 |

The `EJBCA_*` names without the `AGENT_` prefix also work. The credential JSON is one of:

```json
{
  "authMethod": "CLIENT_CERT",
  "baseUrl": "https://ejbca.internal.example.com:8443",
  "clientP12Base64": "<base64 of the .p12>",
  "clientP12Password": "<password>",
  "serverCaChainPem": "<PEM chain of EJBCA's own TLS certificate>"
}
```

```json
{
  "authMethod": "OAUTH_CLIENT_CREDENTIALS",
  "baseUrl": "https://ejbca.internal.example.com:8443",
  "tokenUrl": "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token",
  "clientId": "<client-id>",
  "clientSecret": "<client-secret>",
  "scope": "api://ejbca/.default",
  "serverCaChainPem": "<PEM chain>"
}
```

`baseUrl` is scheme, host and port only, over HTTPS. Without `serverCaChainPem` the agent uses the
system trust store; it never turns verification off. With `CLIENT_CERT` the certificate's common
name must be an EJBCA role member; with OAuth the token's subject must be. If the TLS connection
drops with nothing in the EJBCA log, EJBCA does not trust the CA that issued the client
certificate.

Each device becomes one end entity, named from the device ID and then the CSR's common name, so
renewals reuse it.

**Your EJBCA profile decides the certificate.** The stock `ENDUSER` and `EMPTY` profiles sign an
RSA-512 request without complaint and ignore a requested validity. A production profile must set
allowed key algorithms and sizes, and enable Allow Validity Override, Allow Extension Override and
Allow Key Usage Override if the Intune profile's settings should apply. `EMPTY` requires a subject
common name. The agent does not pass the Intune profile's validity to EJBCA, so the certificate
profile's validity is what devices get.

#### Smallstep step-ca

Uses a JWK provisioner.

| Variable | Meaning |
| --- | --- |
| `AGENT_SMALLSTEP_ENABLED` | `true` |
| `AGENT_SMALLSTEP_CREDENTIAL_PATH` or `AGENT_SMALLSTEP_CREDENTIALS_JSON` | Handle to, or the text of, `{"baseUrl", "authorityName", "provisionerName", "provisionerPrivateJwk", "rootCaPem"}`. `baseUrl` must be HTTPS. |
| `AGENT_SMALLSTEP_BASE_URL` | Optional override of `baseUrl` |

Turn on CRLs in step-ca with `generateOnRevoke: true`. The agent checks the signed CRL before
revocation and renewal decisions and refuses to revoke when no CRL endpoint is configured.

The agent asks step-ca for the Intune profile's validity (`notAfter`, for example `8760h` for 12
months; a month counts as 730 hours). It finds that validity by reading the Intune SCEP profiles
whose SCEP server URL is the endpoint's URL, cached for 10 minutes. When several profiles share the
URL and their validity differs, or the lookup fails, step-ca's default applies. Raise the
provisioner's `maxTLSCertDuration` to at least the longest profile validity, or step-ca refuses
the request.

#### CA health

Every 5 minutes the agent reports each enabled CA as `HEALTHY`, `DEGRADED`, `UNCONFIGURED`,
`UNREACHABLE` (network, TLS or API off), `UNAUTHORIZED` (credential rejected) or `ERROR`, with a
remediation hint. The web app shows it per connector.

### The SCEP endpoint

| Variable | Meaning |
| --- | --- |
| `SCEP_ENABLED` | `true` to serve SCEP. Off by default |
| `SCEP_PUBLIC_BASE_URL` | HTTPS scheme and host devices use, for example `https://scep.example.com`. Written into every Intune profile |
| `SCEP_CA_BACKEND` | `ejbca` or `smallstep`; that CA must be enabled |
| `SCEP_RA_KEYSTORE_HANDLE` | Secret-store handle of `{"p12":"<base64 PKCS#12>","password":"..."}`: the RSA key and certificate the endpoint signs SCEP replies with (see below) |
| `SCEP_INTUNE_ENABLED` | `true`; every request's challenge is checked with Intune and the result reported back |

The RA keystore holds an RSA key of at least 2048 bits and a certificate issued by your CA, and its
chain must include every CA certificate up to and including the root. GetCACert returns that
chain, and Windows looks in it for the root of the profile's trusted certificate profile; without
the root, enrollment fails on the device with "The hash value is not correct". The agent refuses to
start with a chain that does not end at a self-signed root. With step-ca:

```sh
step ca certificate "CertPing SCEP RA" ra.crt ra.key --kty RSA --size 2048 --not-after 2160h
step certificate p12 ra.p12 ra.crt ra.key --ca root_ca.crt
```

Store it as the JSON above. In the `LOCAL` store the name must start with `certping-` (for example
`local:certping-scep-ra`); the agent does not read other names.

The endpoint is the one inbound port an agent opens: devices connect to it. Put it behind your
HTTPS ingress or load balancer and expose only `/scep/*`.

Each source is served at `<SCEP_PUBLIC_BASE_URL>/scep/v1/<profile-ref>`, and at
`/scep/v1/default` while exactly one Intune source exists. A device makes three calls per
enrollment; behind a load balancer all three must reach the same agent. Until SCEP is enabled with
a public URL, creating or updating an Intune profile fails with `SCEP_ENDPOINT_NOT_CONFIGURED`;
discovering existing profiles works without it.

### Certificate profiles

Native create and update support Intune Windows SCEP profiles (through Graph beta). Discovery
imports any certificate-related Intune profile as read-only. With each create or update the agent
also creates or updates a Windows trusted certificate profile named after the SCEP profile with
`(trusted root)` added, holding the root of the SCEP CA chain, and links it to the SCEP profile. It
replaces the root only when the CA root changed. Rules the API enforces for a Windows SCEP
profile:

- RSA 2048 or 4096; 4096 needs the software key storage provider.
- Hash SHA-2.
- Key usage: digital signature, key encipherment, or both.
- SAN types: email, UPN, DNS and URI only. Intune has no IP or other-name SAN.
- Renewal threshold as a percentage of lifetime, 1 to 99.
- Assignment groups (optional, `providerConfig.assignmentGroupIds`): up to 20 Entra group object
  IDs. When set, the agent assigns the SCEP profile and its trusted root profile to exactly these
  groups, replacing their earlier assignments, so Intune deploys them. When left out, assignments
  in Intune are not touched.
- Changing an assigned profile can make Intune reissue certificates, so the change must be
  confirmed.

Intune limits worth knowing: validity up to 24 months, and at least five days in practice; the
subject format can use `{{variables}}`, and a device must have every variable it uses; the profile
needs a trusted certificate profile for your root CA, which the agent creates as described above.

A certificate issued through SCEP is linked to its profile when exactly one Intune SCEP profile
uses the endpoint's URL; the SCEP request itself does not name the profile.

### Renewal and revocation

Renewal is started by the device when it crosses the profile's renewal threshold; it looks
like a new enrollment. The old certificate stays valid until it expires, unless your CA revokes it
(EJBCA: Single Active Certificate Constraint). On iOS, iPadOS and macOS a missed renewal is not
retried by Intune; exclude the device from the profile and add it back.

Revocation after a wipe or unenrollment comes from Intune: the agent fetches Intune's queued
revocation requests, revokes at the CA and reports the results. Intune allows one fetch per 60
minutes, so revocation can lag by up to an hour. Intune does not revoke certificates for Android
Enterprise Device Owner or AOSP devices; revoke those at the CA.

