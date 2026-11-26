// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { CredentialRecord } from "@/types/ssl";

const KUBERNETES_SECRETS = "KUBERNETES_SECRETS";

const AWS_PROVIDERS = new Set([
  "AWS_ACM",
  "AWS_ALB",
  "AWS_NLB",
  "AWS_API_GW_REST",
  "AWS_API_GW_HTTP",
  "AWS_CLOUDFRONT",
  "AWS_ORGANIZATION",
]);

const AZURE_PROVIDERS = new Set([
  "AZURE_KV",
  "AZURE_APP_GW",
  "AZURE_APP_GW_CONTAINERS",
  "AZURE_AFD",
]);

const GCP_PROVIDERS = new Set([
  "GCP_CERT_MANAGER",
  "GCP_ALB",
  "GCP_PROXY_NLB",
  "GCP_API_GW",
  "GCP_CLOUD_CDN",
]);

export type DiscoveryCredentialIneligibilityReason = "missing_kv_path";

function resolveProvider(credential: CredentialRecord): string {
  return (
    credential.targetType ||
    credential.providerName ||
    credential.provider ||
    ""
  )
    .trim()
    .toUpperCase();
}

function hasKvPath(credential: CredentialRecord): boolean {
  return Boolean(credential.secretHandle?.trim());
}

function normalizeConfigRoot(configJson: string | undefined): unknown {
  if (!configJson?.trim()) {
    return null;
  }

  try {
    const parsed = JSON.parse(configJson) as unknown;
    if (parsed && typeof parsed === "object" && "config" in parsed) {
      return (parsed as { config?: unknown }).config ?? null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function extractConfigField(
  configJson: string | undefined,
  fieldName: string,
): string | null {
  const root = normalizeConfigRoot(configJson);
  if (!root || typeof root !== "object") {
    return null;
  }

  const value = (root as Record<string, unknown>)[fieldName];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function extractAuthMode(configJson: string | undefined): string | null {
  return extractConfigField(configJson, "authMode");
}

function extractAuthMethod(configJson: string | undefined): string | null {
  return extractConfigField(configJson, "authMethod");
}

/** Mirrors the server's {@code DiscoveryCredentialPolicy.allowsNullKvPath}. */
function allowsNullKvPath(
  provider: string,
  configJson: string | undefined,
): boolean {
  if (
    provider === KUBERNETES_SECRETS &&
    extractAuthMethod(configJson) === "SA_INCLUSTER"
  ) {
    return true;
  }

  const authMode = extractAuthMode(configJson);
  if (
    AWS_PROVIDERS.has(provider) &&
    (authMode === "INSTANCE_PROFILE" || authMode === "ASSUME_ROLE")
  ) {
    return true;
  }
  if (AZURE_PROVIDERS.has(provider) && authMode === "WORKLOAD_IDENTITY") {
    return true;
  }
  if (GCP_PROVIDERS.has(provider) && authMode === "WORKLOAD_IDENTITY") {
    return true;
  }

  return false;
}

export function getDiscoveryCredentialIneligibilityReason(
  credential: CredentialRecord,
): DiscoveryCredentialIneligibilityReason | null {
  const provider = resolveProvider(credential);
  const configJson = credential.configJson;

  if (hasKvPath(credential) || allowsNullKvPath(provider, configJson)) {
    return null;
  }

  return "missing_kv_path";
}

export function isDiscoveryCredentialEligible(
  credential: CredentialRecord,
): boolean {
  return getDiscoveryCredentialIneligibilityReason(credential) === null;
}

export function getDiscoveryCredentialIneligibilityMessage(
  reason: DiscoveryCredentialIneligibilityReason,
): string {
  switch (reason) {
    case "missing_kv_path":
      return "This credential has no secret handle configured. Add a secret handle or use an ambient auth mode supported for discovery.";
  }
}
