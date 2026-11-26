// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const AZURE_APP_GW_AUTH_MODES = [
  "SERVICE_PRINCIPAL",
  "WORKLOAD_IDENTITY",
] as const;
export type AzureAppGwAuthMode = (typeof AZURE_APP_GW_AUTH_MODES)[number];

const httpsUrlSchema = z
  .string()
  .trim()
  .url("Must be a valid URL")
  .refine((value) => /^https:\/\//i.test(value), "Must be an HTTPS URL");

/**
 * Azure Application Gateway credential scope config.
 *
 * One credential = one App Gateway.
 * Per-certificate targets live separately in the deployment-target configuration UI.
 */
export const azureAppGwCredentialConfigSchema = z.object({
  authMode: z.enum(AZURE_APP_GW_AUTH_MODES),
  tenantId: z.string().trim().min(1, "Tenant ID is required"),
  subscriptionId: z.string().trim().min(1, "Subscription ID is required"),
  // Optional override for Workload Identity when multiple identities exist.
  clientId: z.string().trim().optional(),
  resourceGroup: z.string().trim().min(1, "Resource group is required"),
  appGateway: z.string().trim().min(1, "Application Gateway name is required"),
  listeners: z
    .array(z.string().trim().min(1, "Listener name is required"))
    .min(1, "At least one listener is required"),
  keyVaultUri: httpsUrlSchema,
});

export type AzureAppGwCredentialConfig = z.infer<
  typeof azureAppGwCredentialConfigSchema
>;

export function parseAzureAppGwCredentialConfig(
  configJson?: unknown,
): AzureAppGwCredentialConfig | null {
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
    const result = azureAppGwCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isAzureAppGwProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AZURE_APP_GW";
}

export function isAzureAppGwKvPathRequired(mode: AzureAppGwAuthMode): boolean {
  return mode !== "WORKLOAD_IDENTITY";
}
