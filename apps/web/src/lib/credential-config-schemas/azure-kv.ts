// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

export const AZURE_KV_AUTH_MODES = [
  "SERVICE_PRINCIPAL",
  "WORKLOAD_IDENTITY",
] as const;

export type AzureKvAuthMode = (typeof AZURE_KV_AUTH_MODES)[number];

const vaultUriSchema = z.string().trim().min(1, "Vault URI is required");
const tenantIdSchema = z.string().trim().min(1, "Tenant ID is required");

export const azureKvCredentialConfigSchema = z.object({
  authMode: z.enum(AZURE_KV_AUTH_MODES),
  vaultUri: vaultUriSchema,
  tenantId: tenantIdSchema,
  // Optional override for Workload Identity when multiple identities exist.
  clientId: z.string().trim().optional(),
});

export type AzureKvCredentialConfig = z.infer<
  typeof azureKvCredentialConfigSchema
>;

const AUTH_MODE_LABELS: Record<AzureKvAuthMode, string> = {
  SERVICE_PRINCIPAL: "Service principal (client secret)",
  WORKLOAD_IDENTITY: "Workload identity",
};

const AUTH_MODE_HELP: Record<AzureKvAuthMode, string> = {
  SERVICE_PRINCIPAL:
    "Store clientId/clientSecret in your secret manager and reference them via a secret handle.",
  WORKLOAD_IDENTITY:
    "No secret handle required. The agent uses its runtime identity (AKS Workload Identity / Managed Identity) to access Key Vault.",
};

const AUTH_MODE_SECRET_TEMPLATES: Record<AzureKvAuthMode, string> = {
  SERVICE_PRINCIPAL: JSON.stringify(
    {
      clientId: "AZURE_CLIENT_ID",
      clientSecret: "AZURE_CLIENT_SECRET",
    },
    null,
    2,
  ),
  WORKLOAD_IDENTITY: JSON.stringify(
    {
      note: "No secret handle required for workload identity",
    },
    null,
    2,
  ),
};

export function parseAzureKvCredentialConfig(
  configJson?: unknown,
): AzureKvCredentialConfig | null {
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
    const result = azureKvCredentialConfigSchema.safeParse(normalized);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

export function getAzureKvAuthModeLabel(mode: AzureKvAuthMode): string {
  return AUTH_MODE_LABELS[mode];
}

export function getAzureKvAuthModeHelp(mode: AzureKvAuthMode): string {
  return AUTH_MODE_HELP[mode];
}

export function getAzureKvAuthModeSecretTemplate(
  mode: AzureKvAuthMode,
): string {
  return AUTH_MODE_SECRET_TEMPLATES[mode];
}

export function isAzureKvProvider(value?: string): boolean {
  return (value || "").trim().toUpperCase() === "AZURE_KV";
}

export function isAzureKvKvPathRequired(mode: AzureKvAuthMode): boolean {
  return mode !== "WORKLOAD_IDENTITY";
}
