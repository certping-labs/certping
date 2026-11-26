// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";

export type AgentConnectionStatus = "ONLINE" | "OFFLINE" | "NEVER_SEEN";
export type AgentSecretStore =
  "LOCAL" | "AZURE_KV" | "AWS_SECRETS_MANAGER" | "GCP_SECRET_MANAGER";
export type AcmeEnvironment = "PRODUCTION" | "STAGING" | "CUSTOM";

export interface AgentAcmeSettings {
  directoryUrl: string;
  environment: AcmeEnvironment;
  contactEmail: string | null;
}

export interface AgentCapabilities {
  deploymentTargets: string[];
  discoveryTargets: string[];
  dnsProviders: string[];
}

/**
 * An agent as `GET /api/v1/agents` reports it. Settings the agent has not reported yet (an older
 * agent, or one that never connected) are null. No secret value is ever part of it.
 */
export interface Agent {
  agentId: string | number;
  name: string;
  tokenPrefix: string;
  tokenCreatedAt: string | null;
  tokenExpiresAt: string | null;
  revoked: boolean;
  status: AgentConnectionStatus;
  lastSeenAt: string | null;
  version: string | null;
  hostname: string | null;
  os: string | null;
  javaVersion: string | null;
  secretStore: AgentSecretStore | string | null;
  maxConcurrentJobs: number | null;
  proxyConfigured: boolean | null;
  bundled: boolean;
  acme: AgentAcmeSettings | null;
  globalsignConfigured: boolean | null;
  capabilities: AgentCapabilities;
}

export const AGENT_DOCS = {
  configuration:
    "https://github.com/certping-labs/certping/blob/main/docs/configuration.md",
  agents: "https://github.com/certping-labs/certping/blob/main/docs/agents.md",
} as const;

/**
 * The environment variable on the agent that changes each setting. Each name is read by the
 * agent: apps/agent/src/main/resources/application*.yml, and HTTPS_PROXY by GatewayClient.
 */
export const AGENT_SETTING_ENV = {
  secretStore: "AGENT_SECRET_STORE_PROVIDER",
  maxConcurrentJobs: "CERTPING_AGENT_MAX_CONCURRENT_JOBS",
  acmeDirectoryUrl: "ACME_DIRECTORY_URL",
  acmeAccountEmail: "ACME_ACCOUNT_EMAIL",
  proxy: "HTTPS_PROXY",
  globalsign: "AGENT_GLOBALSIGN_API_KEY",
} as const;

const SECRET_STORE_LABELS: Record<string, string> = {
  LOCAL: "Local encrypted files",
  AZURE_KV: "Azure Key Vault",
  AWS_SECRETS_MANAGER: "AWS Secrets Manager",
  GCP_SECRET_MANAGER: "Google Secret Manager",
};

export function secretStoreLabel(value: string | null | undefined): string {
  if (!value) return "Not reported";
  return SECRET_STORE_LABELS[value.trim().toUpperCase()] ?? value;
}

const ACME_ENVIRONMENT_LABELS: Record<string, string> = {
  PRODUCTION: "Production",
  STAGING: "Staging (test certificates)",
  CUSTOM: "Custom CA",
};

export function acmeEnvironmentLabel(value: string | null | undefined): string {
  if (!value) return "Unknown";
  return ACME_ENVIRONMENT_LABELS[value.trim().toUpperCase()] ?? value;
}

export type AgentStatusKey = AgentConnectionStatus | "REVOKED";

/** Revoked wins over the connection state: a revoked agent cannot connect again. */
export function agentStatusKey(
  agent: Pick<Agent, "revoked" | "status">,
): AgentStatusKey {
  if (agent.revoked) return "REVOKED";
  return agent.status;
}

export const AGENT_STATUS_LABELS: Record<AgentStatusKey, string> = {
  ONLINE: "Online",
  OFFLINE: "Offline",
  NEVER_SEEN: "Never connected",
  REVOKED: "Revoked",
};

export const listAgents = async (): Promise<Agent[]> => {
  const response = await apiClient.get<{ agents?: Agent[] }>(
    apiRoutes.query.agent.agents,
  );
  return response.data?.agents ?? [];
};

export const getAgent = async (agentId: string | number): Promise<Agent> => {
  const response = await apiClient.get<Agent>(
    apiRoutes.query.agent.agentById(agentId),
  );
  return response.data;
};

export interface AgentHealthCheckStarted {
  deepCheckId?: string | null;
  requestedAt?: string | null;
}

export const startAgentHealthCheck = async (
  agentId: string | number,
): Promise<AgentHealthCheckStarted | null> => {
  const response = await apiClient.post<AgentHealthCheckStarted | null>(
    apiRoutes.mutation.agent.runHealthCheck(agentId),
  );
  return response.data;
};

export type DeepHealthCheckStatus =
  "PENDING" | "IN_PROGRESS" | "SUCCESS" | "PARTIAL" | "FAILED" | "TIMED_OUT";

export interface DeepHealthCheck {
  deepCheckId: string;
  status: DeepHealthCheckStatus;
  errorMessage?: string | null;
}

export interface DeepHealthMetric {
  metricKey: string;
  metricName?: string | null;
  status: string;
  path?: string | null;
  message?: string | null;
}

export const isDeepHealthCheckDone = (status?: DeepHealthCheckStatus) =>
  status === "SUCCESS" ||
  status === "PARTIAL" ||
  status === "FAILED" ||
  status === "TIMED_OUT";

export const getDeepHealthCheck = async (
  deepCheckId: string,
): Promise<DeepHealthCheck> => {
  const response = await apiClient.get<DeepHealthCheck>(
    apiRoutes.query.agent.deepCheck(deepCheckId),
  );
  return response.data;
};

export const getDeepHealthCheckMetrics = async (
  deepCheckId: string,
): Promise<DeepHealthMetric[]> => {
  const response = await apiClient.get<DeepHealthMetric[]>(
    apiRoutes.query.agent.deepCheckMetrics(deepCheckId),
  );
  return response.data ?? [];
};

const AGENT_IMAGE = "ghcr.io/certping-labs/certping-agent";

/** The agent image tag in the server's Docker command, which is the server's own release. */
export function agentImageTag(dockerCommand: string | null | undefined) {
  const match = /ghcr\.io\/certping-labs\/certping-agent:(\S+)/.exec(
    dockerCommand ?? "",
  );
  return match ? match[1] : null;
}

/** A store a remote agent can use: LOCAL belongs to the agent bundled with the server. */
export type RemoteAgentSecretStore = Exclude<AgentSecretStore, "LOCAL">;

/** Where a new agent keeps private keys and credentials, in the order Add agent offers them. */
export const AGENT_SECRET_STORE_CHOICES: ReadonlyArray<{
  value: RemoteAgentSecretStore;
  label: string;
}> = [
  { value: "AWS_SECRETS_MANAGER", label: "AWS Secrets Manager" },
  { value: "AZURE_KV", label: "Azure Key Vault" },
  { value: "GCP_SECRET_MANAGER", label: "Google Secret Manager" },
];

export interface AgentCommandInput {
  store: RemoteAgentSecretStore;
  serverUrl: string;
  token: string;
  imageTag: string | null;
}

/**
 * The secret store part of `docker run`, using the identity of the host the agent runs on:
 * the instance's IAM role on AWS, a managed identity on Azure, the attached service account
 * on Google Cloud. No cloud secret goes in the command.
 */
function dockerStoreArgs(store: RemoteAgentSecretStore): {
  comment: string;
  args: string[];
} {
  switch (store) {
    case "AWS_SECRETS_MANAGER":
      return {
        comment:
          "# Uses the IAM role of the host (EC2 instance profile or ECS task role).",
        args: [
          "-e AGENT_SECRET_STORE_PROVIDER=AWS_SECRETS_MANAGER",
          "-e AWS_REGION=<your-aws-region>",
          "-e AWS_SM_AUTH_MODE=DEFAULT",
        ],
      };
    case "AZURE_KV":
    default:
      return {
        comment:
          "# Uses the managed identity of the host (Azure VM or container).",
        args: [
          "-e AGENT_SECRET_STORE_PROVIDER=AZURE_KV",
          "-e CLIENT_KV_URI=https://<your-vault-name>.vault.azure.net",
          "-e AZURE_KV_AUTH_MODE=DEFAULT",
        ],
      };
    case "GCP_SECRET_MANAGER":
      return {
        comment:
          "# Uses the service account attached to the host (Application Default Credentials).",
        args: [
          "-e AGENT_SECRET_STORE_PROVIDER=GCP_SECRET_MANAGER",
          "-e GCP_PROJECT_ID=<your-project-id>",
          "-e GCP_SM_AUTH_MODE=ADC",
        ],
      };
  }
}

export function buildDockerCommand({
  store,
  serverUrl,
  token,
  imageTag,
}: AgentCommandInput): string {
  const { comment, args } = dockerStoreArgs(store);
  const run = [
    "docker run -d --name certping-agent --restart unless-stopped",
    "-e SPRING_PROFILES_ACTIVE=selfhosted",
    `-e CERTPING_SERVER_URL=${serverUrl}`,
    `-e CERTPING_AGENT_TOKEN=${token}`,
    ...args,
    `${AGENT_IMAGE}:${imageTag ?? "latest"}`,
  ].join(" \\\n  ");
  return `${comment}\n${run}`;
}

/** Chart values for each cloud store, with the workload identity of the cluster. */
function helmStoreArgs(store: RemoteAgentSecretStore): {
  comment: string;
  args: string[];
} {
  switch (store) {
    case "AWS_SECRETS_MANAGER":
      return {
        comment:
          "# EKS IRSA: the role's trust policy must allow this service account.",
        args: [
          "--set secretStore.provider=AWS_SECRETS_MANAGER",
          "--set secretStore.awsSecretsManager.region=<your-aws-region>",
          "--set secretStore.awsSecretsManager.authMode=DEFAULT",
          "--set 'serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn=arn:aws:iam::<account-id>:role/<role-name>'",
        ],
      };
    case "GCP_SECRET_MANAGER":
      return {
        comment:
          "# GKE Workload Identity: bind roles/iam.workloadIdentityUser on the Google service account to this service account.",
        args: [
          "--set secretStore.provider=GCP_SECRET_MANAGER",
          "--set secretStore.gcpSecretManager.projectId=<your-project-id>",
          "--set secretStore.gcpSecretManager.authMode=ADC",
          "--set 'serviceAccount.annotations.iam\\.gke\\.io/gcp-service-account=<service-account-name>@<your-project-id>.iam.gserviceaccount.com'",
        ],
      };
    case "AZURE_KV":
    default:
      return {
        comment:
          "# AKS workload identity: a federated credential on the managed identity for this service account.",
        args: [
          "--set secretStore.provider=AZURE_KV",
          "--set secretStore.azureKv.vaultUri=https://<your-vault-name>.vault.azure.net",
          "--set secretStore.azureKv.authMode=WORKLOAD_IDENTITY",
          "--set 'serviceAccount.annotations.azure\\.workload\\.identity/client-id=<managed-identity-client-id>'",
          "--set-string 'podLabels.azure\\.workload\\.identity/use=true'",
        ],
      };
  }
}

/**
 * Installs deploy/charts/certping-agent with the token in a Secret (the chart's default
 * tokenSecret name and key).
 */
export function buildHelmCommand({
  store,
  serverUrl,
  token,
  imageTag,
}: AgentCommandInput): string {
  const { comment, args } = helmStoreArgs(store);
  const install = [
    "helm install certping-agent ./deploy/charts/certping-agent",
    `--set serverUrl=${serverUrl}`,
    "--set tokenSecret.name=certping-agent-token",
    "--set tokenSecret.key=token",
    ...(imageTag ? [`--set image.tag=${imageTag}`] : []),
    ...args,
  ].join(" \\\n  ");
  return [
    "# Run from a checkout of github.com/certping-labs/certping",
    `kubectl create secret generic certping-agent-token --from-literal=token=${token}`,
    comment,
    install,
  ].join("\n");
}
