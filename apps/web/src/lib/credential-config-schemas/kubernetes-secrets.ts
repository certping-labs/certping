// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";
import type { KubernetesNamespaceSecretMap } from "@/types/cert-manager";

export const KUBERNETES_SECRETS_PROVIDER = "KUBERNETES_SECRETS";
export const KUBERNETES_ALL_NAMESPACES = "all_namespaces";
export const KUBERNETES_AUTH_METHODS = [
  "SA_INCLUSTER",
  "SA_TOKEN",
  "AWS",
  "AZURE",
  "GCP",
] as const;

export type KubernetesAuthMethod = (typeof KUBERNETES_AUTH_METHODS)[number];

// Auth methods offered when the credential is pasted into CertPing. A service account token
// works with any distribution (k3s, kubeadm, OpenShift, on-prem); in-cluster needs no secret.
export const MANAGED_KUBERNETES_AUTH_METHODS: KubernetesAuthMethod[] = [
  "SA_TOKEN",
  "SA_INCLUSTER",
  "AWS",
  "AZURE",
  "GCP",
];

const namespaceSchema = z
  .string()
  .trim()
  .min(1, "Namespace is required")
  .regex(
    /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/,
    "Namespace must be lowercase and can include dashes",
  );
const secretNameSchema = z
  .string()
  .trim()
  .min(1, "Secret name is required")
  .regex(
    /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/,
    "Secret name must be lowercase and can include dashes or dots",
  );

const clusterNameSchema = z.string().trim().min(1, "Cluster name is required");

const namespacesValueSchema = z.union([
  z.literal(KUBERNETES_ALL_NAMESPACES),
  z.array(namespaceSchema).min(1, "At least one namespace is required"),
]);

export const kubernetesCredentialConfigSchema = z.object({
  authMethod: z.enum(KUBERNETES_AUTH_METHODS),
  clusterName: clusterNameSchema,
  namespaces: namespacesValueSchema,
});

export type KubernetesCredentialConfig = z.infer<
  typeof kubernetesCredentialConfigSchema
>;

export interface NamespaceSecretPair {
  namespace: string;
  secretName: string;
}

export type KubernetesNsMapMode = "explicit" | "all_namespaces";

export interface KubernetesNsSecretDraft {
  mapMode: KubernetesNsMapMode;
  pairs: NamespaceSecretPair[];
  allNamespacesSecret: string;
}

const AUTH_METHOD_LABELS: Record<KubernetesAuthMethod, string> = {
  SA_INCLUSTER: "In-cluster service account",
  SA_TOKEN: "Kubernetes (service account token)",
  AWS: "AWS (EKS)",
  AZURE: "Azure (AKS)",
  GCP: "GCP (GKE)",
};

const AUTH_METHOD_INSTRUCTIONS: Record<KubernetesAuthMethod, string> = {
  SA_INCLUSTER:
    "The CertPing agent runs in this cluster and uses its own pod service account and RBAC. No secret is needed.",
  SA_TOKEN:
    "Works with any Kubernetes distribution. Store the API server URL, service account token and cluster CA certificate in your secret manager, then give the secret handle here.",
  AWS: "Store EKS auth details in Key Vault. You can use static keys, role-assume flow, or workload identity bootstrap with role ARN.",
  AZURE:
    "Store AKS auth metadata in Key Vault. Use client-secret auth or workload identity (federated token) at runtime.",
  GCP: "Store GKE project/location metadata in Key Vault. Use service-account JSON or workload identity (ADC).",
};

const AUTH_METHOD_SECRET_TEMPLATES: Record<KubernetesAuthMethod, string> = {
  SA_INCLUSTER: JSON.stringify(
    {
      note: "No secret handle required for SA_INCLUSTER",
    },
    null,
    2,
  ),
  SA_TOKEN: JSON.stringify(
    {
      apiServer: "https://YOUR_CLUSTER_API_SERVER",
      caCertBase64: "BASE64_ENCODED_CA_PEM",
      bearerToken: "K8S_BEARER_TOKEN",
    },
    null,
    2,
  ),
  AWS: JSON.stringify(
    {
      awsRegion: "us-east-1",
      awsRoleArn: "arn:aws:iam::123456789012:role/certping-eks-deployer",
      awsAccessKeyId: "ACCESS_KEY_ID",
      awsSecretAccessKey: "SECRET_ACCESS_KEY",
    },
    null,
    2,
  ),
  AZURE: JSON.stringify(
    {
      azureTenantId: "11111111-1111-1111-1111-111111111111",
      azureSubscriptionId: "22222222-2222-2222-2222-222222222222",
      azureResourceGroup: "rg-prod",
      azureClientId: "33333333-3333-3333-3333-333333333333",
      azureClientSecret: "OPTIONAL_FOR_WORKLOAD_IDENTITY",
    },
    null,
    2,
  ),
  GCP: JSON.stringify(
    {
      gcpProjectId: "project-123",
      gcpLocation: "us-central1",
      gcpServiceAccountJson: "OPTIONAL_RAW_JSON_STRING",
    },
    null,
    2,
  ),
};

function sanitizeNamespacesList(values: string[]): string[] {
  const seen = new Set<string>();
  const namespaces: string[] = [];

  for (const token of values) {
    const normalized = token.trim();
    if (!normalized) {
      continue;
    }
    if (seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    namespaces.push(normalized);
  }

  return namespaces;
}

export function parseNamespacesInput(value: string): string[] {
  return sanitizeNamespacesList(value.split(","));
}

export function parseCredentialNamespacesInput(
  value: string | string[],
): KubernetesCredentialConfig["namespaces"] {
  if (Array.isArray(value)) {
    const sanitized = sanitizeNamespacesList(value);
    if (sanitized.length === 1 && sanitized[0] === KUBERNETES_ALL_NAMESPACES) {
      return KUBERNETES_ALL_NAMESPACES;
    }
    return sanitized;
  }

  if (value.trim() === KUBERNETES_ALL_NAMESPACES) {
    return KUBERNETES_ALL_NAMESPACES;
  }

  return parseNamespacesInput(value);
}

export function parseKubernetesCredentialConfig(
  configJson?: unknown,
): KubernetesCredentialConfig | null {
  if (!configJson) {
    return null;
  }

  try {
    const parsed =
      typeof configJson === "string"
        ? (JSON.parse(configJson) as unknown)
        : configJson;
    const normalized =
      parsed && typeof parsed === "object" && "config" in parsed
        ? (parsed as { config?: unknown }).config
        : parsed;
    const result = kubernetesCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function getKubernetesAuthMethodLabel(
  method: KubernetesAuthMethod,
): string {
  return AUTH_METHOD_LABELS[method];
}

export function getKubernetesAuthMethodInstruction(
  method: KubernetesAuthMethod,
): string {
  return AUTH_METHOD_INSTRUCTIONS[method];
}

export function getKubernetesAuthMethodSecretTemplate(
  method: KubernetesAuthMethod,
): string {
  return AUTH_METHOD_SECRET_TEMPLATES[method];
}

export function isKubernetesSecretsTarget(value?: string): boolean {
  return (value || "").trim().toUpperCase() === KUBERNETES_SECRETS_PROVIDER;
}

export function normalizeNamespaceScope(
  namespaces: KubernetesCredentialConfig["namespaces"] | undefined,
): { allNamespaces: boolean; namespaces: string[] } {
  if (!namespaces) {
    return { allNamespaces: false, namespaces: [] };
  }

  if (namespaces === KUBERNETES_ALL_NAMESPACES) {
    return { allNamespaces: true, namespaces: [] };
  }

  return { allNamespaces: false, namespaces };
}

export function sanitizeDomainForSecretBase(domain: string): string {
  const normalized = domain
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/\.+$/, "")
    .replace(/[^a-z0-9.-]/g, "-")
    .replace(/\./g, "-")
    .replace(/-+/g, "-");
  const trimmed = normalized.replace(/^-+/, "").replace(/-+$/, "");
  return trimmed || "tls";
}

export function generateDefaultTlsSecretName(
  domain: string,
  namespace?: string,
): string {
  const base = sanitizeDomainForSecretBase(domain);
  if (namespace) {
    return `${base}-${namespace}-tls`;
  }
  return `${base}-tls`;
}

export function parseNamespaceSecretPairs(text: string): NamespaceSecretPair[] {
  const lines = text.split(/\n/);
  const pairs: NamespaceSecretPair[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const [left, ...right] = trimmed.split("=");
    const namespace = (left || "").trim();
    const secretName = right.join("=").trim();

    pairs.push({ namespace, secretName });
  }

  return sanitizeNamespaceSecretPairs(pairs);
}

export function buildNsSecretMapFromPairs(
  pairs: NamespaceSecretPair[],
): KubernetesNamespaceSecretMap {
  return pairs.map((pair) => ({ [pair.namespace]: pair.secretName }));
}

export function buildAllNamespacesSecretMap(
  secretName: string,
): KubernetesNamespaceSecretMap {
  return { [KUBERNETES_ALL_NAMESPACES]: validateSecretName(secretName) };
}

export function getDefaultNamespaceSecretPairs(
  domain: string,
  namespaces: string[],
): NamespaceSecretPair[] {
  return namespaces.map((namespace) => ({
    namespace,
    secretName: generateDefaultTlsSecretName(domain, namespace),
  }));
}

export function validateNamespace(value: string): string {
  const validation = namespaceSchema.safeParse(value.trim());
  if (!validation.success) {
    throw new Error(validation.error.issues[0]?.message || "Invalid namespace");
  }
  return validation.data;
}

export function validateSecretName(value: string): string {
  const validation = secretNameSchema.safeParse(value.trim());
  if (!validation.success) {
    throw new Error(
      validation.error.issues[0]?.message || "Invalid secret name",
    );
  }
  return validation.data;
}

export function sanitizeNamespaceSecretPairs(
  pairs: NamespaceSecretPair[],
): NamespaceSecretPair[] {
  const normalized: NamespaceSecretPair[] = [];
  const seen = new Set<string>();

  for (const pair of pairs) {
    const namespace = validateNamespace(pair.namespace);
    const secretName = validateSecretName(pair.secretName);

    if (seen.has(namespace)) {
      continue;
    }

    seen.add(namespace);
    normalized.push({ namespace, secretName });
  }

  return normalized;
}

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

export function parseKubernetesNsSecretMap(
  value: unknown,
): KubernetesNsSecretDraft | null {
  if (Array.isArray(value)) {
    const pairs: NamespaceSecretPair[] = [];

    for (const item of value) {
      const record = asRecord(item);
      if (!record) {
        continue;
      }

      for (const [namespace, secretNameValue] of Object.entries(record)) {
        if (typeof secretNameValue !== "string") {
          continue;
        }
        pairs.push({ namespace, secretName: secretNameValue });
      }
    }

    const normalizedPairs = sanitizeNamespaceSecretPairs(pairs);
    return {
      mapMode: "explicit",
      pairs: normalizedPairs,
      allNamespacesSecret: "",
    };
  }

  const record = asRecord(value);
  if (!record) {
    return null;
  }

  const allNamespacesSecret = record[KUBERNETES_ALL_NAMESPACES];
  if (typeof allNamespacesSecret !== "string") {
    return null;
  }

  return {
    mapMode: "all_namespaces",
    pairs: [],
    allNamespacesSecret: validateSecretName(allNamespacesSecret),
  };
}

export function parseSavedKubernetesDeploymentConfig(
  config: Record<string, unknown> | string | null | undefined,
): KubernetesNsSecretDraft | null {
  if (!config) {
    return null;
  }

  let normalizedConfig: Record<string, unknown> | null = null;
  if (typeof config === "string") {
    try {
      const parsed = JSON.parse(config) as unknown;
      normalizedConfig = asRecord(parsed);
    } catch {
      normalizedConfig = null;
    }
  } else {
    normalizedConfig = config;
  }

  if (!normalizedConfig) {
    return null;
  }

  const candidate =
    "nsMaps" in normalizedConfig ? normalizedConfig.nsMaps : normalizedConfig;
  try {
    return parseKubernetesNsSecretMap(candidate);
  } catch {
    return null;
  }
}

interface CreateKubernetesSecretDraftInput {
  domain: string;
  allowedNamespaces: string[];
  supportsAllNamespaces: boolean;
  savedNsSecretMap?: KubernetesNamespaceSecretMap | null;
}

export function createKubernetesSecretDraft({
  domain,
  allowedNamespaces,
  supportsAllNamespaces,
  savedNsSecretMap,
}: CreateKubernetesSecretDraftInput): KubernetesNsSecretDraft {
  const defaultPairs = getDefaultNamespaceSecretPairs(
    domain,
    allowedNamespaces,
  );
  const defaultDraft: KubernetesNsSecretDraft = {
    mapMode: "explicit",
    pairs: defaultPairs,
    allNamespacesSecret: generateDefaultTlsSecretName(domain),
  };

  if (!savedNsSecretMap) {
    return defaultDraft;
  }

  let parsedSavedMap: KubernetesNsSecretDraft | null = null;
  try {
    parsedSavedMap = parseKubernetesNsSecretMap(savedNsSecretMap);
  } catch {
    parsedSavedMap = null;
  }

  if (!parsedSavedMap) {
    return defaultDraft;
  }

  if (parsedSavedMap.mapMode === "all_namespaces") {
    if (!supportsAllNamespaces) {
      return defaultDraft;
    }
    return {
      ...defaultDraft,
      mapMode: "all_namespaces",
      allNamespacesSecret: parsedSavedMap.allNamespacesSecret,
    };
  }

  if (allowedNamespaces.length === 0) {
    return {
      ...defaultDraft,
      pairs: parsedSavedMap.pairs,
    };
  }

  const savedByNamespace = new Map(
    parsedSavedMap.pairs.map((pair) => [pair.namespace, pair.secretName]),
  );
  const pairs = allowedNamespaces.map((namespace) => ({
    namespace,
    secretName:
      savedByNamespace.get(namespace) ||
      generateDefaultTlsSecretName(domain, namespace),
  }));

  return {
    ...defaultDraft,
    pairs,
  };
}
