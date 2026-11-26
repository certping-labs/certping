// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { parseAzureAfdCredentialConfig } from "@/lib/credential-config-schemas/azure-afd";
import { parseAzureKvCredentialConfig } from "@/lib/credential-config-schemas/azure-kv";
import type { CredentialRecord } from "@/types/ssl";

export type DeploymentTargetConfigKind =
  | "KUBERNETES_SECRETS"
  | "AZURE_KV"
  | "GCP_CERT_MANAGER"
  | "AZURE_AFD"
  | "AZURE_APP_GW"
  | "AZURE_APP_GW_CONTAINERS"
  | "AWS_LOAD_BALANCER"
  | "AWS_API_GATEWAY"
  | "NONE";

export function getDeploymentTargetApiValue(
  credential: Pick<CredentialRecord, "targetType" | "providerName">,
): string {
  return (credential.targetType || credential.providerName || "")
    .trim()
    .toUpperCase();
}

export function getDeploymentTargetConfigKind(
  credential: Pick<CredentialRecord, "targetType" | "providerName">,
): DeploymentTargetConfigKind {
  const apiValue = getDeploymentTargetApiValue(credential);

  if (apiValue === "KUBERNETES_SECRETS") {
    return "KUBERNETES_SECRETS";
  }
  if (apiValue === "AZURE_KV") {
    return "AZURE_KV";
  }
  if (apiValue === "GCP_CERT_MANAGER") {
    return "GCP_CERT_MANAGER";
  }
  if (apiValue === "AZURE_AFD") {
    return "AZURE_AFD";
  }
  if (apiValue === "AZURE_APP_GW") {
    return "AZURE_APP_GW";
  }
  if (apiValue === "AZURE_APP_GW_CONTAINERS") {
    return "AZURE_APP_GW_CONTAINERS";
  }
  if (apiValue === "AWS_ALB" || apiValue === "AWS_NLB") {
    return "AWS_LOAD_BALANCER";
  }
  if (apiValue === "AWS_API_GW_REST" || apiValue === "AWS_API_GW_HTTP") {
    return "AWS_API_GATEWAY";
  }

  return "NONE";
}

export function defaultAzureKvCertificateName(domain: string): string {
  const normalized = normalizeDomainNameForResource(domain);
  return normalized || "certificate";
}

export function defaultAzureAppGatewaySslCertName(domain: string): string {
  const normalized = defaultAzureKvCertificateName(domain);
  return `certping-${normalized}`;
}

function normalizeDomainNameForResource(domain: string): string {
  const normalized = domain
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/\.+$/, "")
    .replace(/[^a-z0-9.-]/g, "-")
    .replace(/\./g, "-")
    .replace(/-+/g, "-");
  return normalized.replace(/^-+/, "").replace(/-+$/, "");
}

export function defaultAzureAfdSecretName(domain: string): string {
  const normalized = normalizeDomainNameForResource(domain);
  return normalized ? `${normalized}-afd-secret` : "afd-secret";
}

// Distinct from the Key Vault target default: both write a Key Vault
// certificate, and Front Door breaks if a Key Vault target overwrites its version.
export function defaultAzureAfdCertificateName(domain: string): string {
  const normalized = normalizeDomainNameForResource(domain);
  return normalized ? `${normalized}-afd` : "afd-certificate";
}

export interface KeyVaultCertificateTarget {
  credentialXref: string;
  kind: "AZURE_KV" | "AZURE_AFD";
  vaultUri?: string | null;
  certificateName: string;
}

export function getCredentialKeyVaultUri(
  credential: Pick<
    CredentialRecord,
    "targetType" | "providerName" | "configJson"
  >,
): string | null {
  const apiValue = getDeploymentTargetApiValue(credential);
  if (apiValue === "AZURE_KV") {
    return (
      parseAzureKvCredentialConfig(credential.configJson)?.vaultUri ?? null
    );
  }
  if (apiValue === "AZURE_AFD") {
    return (
      parseAzureAfdCredentialConfig(credential.configJson)?.keyVaultUri ?? null
    );
  }
  return null;
}

const normalizeVaultUri = (uri?: string | null): string =>
  (uri || "").trim().toLowerCase().replace(/\/+$/, "");

export function findKeyVaultCertificateNameCollision(
  targets: KeyVaultCertificateTarget[],
): string | null {
  const kvTargets = targets.filter((target) => target.kind === "AZURE_KV");
  const afdTargets = targets.filter((target) => target.kind === "AZURE_AFD");
  for (const kv of kvTargets) {
    for (const afd of afdTargets) {
      if (
        kv.certificateName.trim().toLowerCase() !==
        afd.certificateName.trim().toLowerCase()
      ) {
        continue;
      }
      const kvVault = normalizeVaultUri(kv.vaultUri);
      const afdVault = normalizeVaultUri(afd.vaultUri);
      if (kvVault && afdVault && kvVault !== afdVault) {
        continue;
      }
      return `Key Vault target ${kv.credentialXref} and Front Door target ${afd.credentialXref} both use certificate name "${kv.certificateName.trim()}" in the same Key Vault. Use a different certificate name for each.`;
    }
  }
  return null;
}
