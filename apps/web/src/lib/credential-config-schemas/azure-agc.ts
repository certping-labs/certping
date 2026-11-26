// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const AZURE_AGC_AUTH_MODES = [
  "SERVICE_PRINCIPAL",
  "WORKLOAD_IDENTITY",
] as const;
export type AzureAgcAuthMode = (typeof AZURE_AGC_AUTH_MODES)[number];

export const AZURE_AGC_CLUSTER_AUTH_MODES = ["AZURE", "SA_INCLUSTER"] as const;
export type AzureAgcClusterAuthMode =
  (typeof AZURE_AGC_CLUSTER_AUTH_MODES)[number];

export const AZURE_AGC_API_STYLES = ["GATEWAY_API", "INGRESS"] as const;
export type AzureAgcApiStyle = (typeof AZURE_AGC_API_STYLES)[number];

/**
 * Azure Application Gateway for Containers (AGC) credential scope.
 *
 * One credential = one cluster + one AGC namespace.
 * Per-certificate targets live separately (TLS secrets per namespace).
 */
export const azureAgcCredentialConfigSchema = z
  .object({
    azureAuthMode: z
      .enum(AZURE_AGC_AUTH_MODES)
      .optional()
      .default("SERVICE_PRINCIPAL"),
    tenantId: z.string().trim().optional().default(""),
    subscriptionId: z.string().trim().optional().default(""),
    resourceGroup: z.string().trim().optional().default(""),
    // Optional override for Workload Identity when multiple identities exist.
    clientId: z.string().trim().optional(),
    clusterAuthMode: z.enum(AZURE_AGC_CLUSTER_AUTH_MODES),
    clusterName: z.string().trim().min(1, "Cluster name is required"),
    agcNamespace: z.string().trim().min(1, "AGC namespace is required"),
    apiStyle: z.enum(AZURE_AGC_API_STYLES).optional().default("GATEWAY_API"),
    secretNamespaces: z
      .array(z.string().trim().min(1, "Namespace is required"))
      .min(1, "At least one secret namespace is required"),
  })
  .superRefine((value, context) => {
    // When authenticating to the cluster via Azure (AKS kubeconfig), we require ARM coordinates.
    if (value.clusterAuthMode === "AZURE") {
      if (!value.tenantId.trim()) {
        context.addIssue({
          code: "custom",
          path: ["tenantId"],
          message: "Tenant ID is required for Azure cluster auth",
        });
      }
      if (!value.subscriptionId.trim()) {
        context.addIssue({
          code: "custom",
          path: ["subscriptionId"],
          message: "Subscription ID is required for Azure cluster auth",
        });
      }
      if (!value.resourceGroup.trim()) {
        context.addIssue({
          code: "custom",
          path: ["resourceGroup"],
          message: "Resource group is required for Azure cluster auth",
        });
      }
    }
  });

export type AzureAgcCredentialConfig = z.infer<
  typeof azureAgcCredentialConfigSchema
>;

export function parseAzureAgcCredentialConfig(
  configJson?: unknown,
): AzureAgcCredentialConfig | null {
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
    const result = azureAgcCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isAzureAgcProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AZURE_APP_GW_CONTAINERS";
}

export function isAzureAgcKvPathRequired(params: {
  azureAuthMode: AzureAgcAuthMode;
  clusterAuthMode: AzureAgcClusterAuthMode;
}): boolean {
  // The secret handle stores the SP credentials used for Azure (and AKS kubeconfig when clusterAuthMode=AZURE).
  if (params.azureAuthMode === "WORKLOAD_IDENTITY") {
    return false;
  }
  if (params.clusterAuthMode === "SA_INCLUSTER") {
    return false;
  }
  return true;
}
