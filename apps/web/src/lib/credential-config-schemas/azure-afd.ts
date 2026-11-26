// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const AZURE_AFD_AUTH_MODES = [
  "SERVICE_PRINCIPAL",
  "WORKLOAD_IDENTITY",
] as const;
export type AzureAfdAuthMode = (typeof AZURE_AFD_AUTH_MODES)[number];

const httpsUrlSchema = z
  .string()
  .trim()
  .url("Must be a valid URL")
  .refine((value) => /^https:\/\//i.test(value), "Must be an HTTPS URL");

export const azureAfdCredentialConfigSchema = z.object({
  authMode: z.enum(AZURE_AFD_AUTH_MODES),
  tenantId: z.string().trim().min(1, "Tenant ID is required"),
  subscriptionId: z.string().trim().min(1, "Subscription ID is required"),
  // Optional override for Workload Identity when multiple identities exist.
  clientId: z.string().trim().optional(),
  resourceGroup: z.string().trim().min(1, "Resource group is required"),
  profileName: z.string().trim().min(1, "Profile name is required"),
  keyVaultUri: httpsUrlSchema,
  customDomains: z
    .array(z.string().trim().min(1, "Domain name is required"))
    .min(1, "At least one custom domain is required"),
});

export type AzureAfdCredentialConfig = z.infer<
  typeof azureAfdCredentialConfigSchema
>;

export function parseAzureAfdCredentialConfig(
  configJson?: unknown,
): AzureAfdCredentialConfig | null {
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
    const result = azureAfdCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function isAzureAfdProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AZURE_AFD";
}

export function isAzureAfdKvPathRequired(mode: AzureAfdAuthMode): boolean {
  return mode !== "WORKLOAD_IDENTITY";
}
