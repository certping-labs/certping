// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { BadgeProps } from "@/components/ui/badge";
import {
  formatProviderLabel,
  resolveCredentialProviderFromApiValue,
} from "@/lib/credential-providers";
import { deploymentTargetDetailsHref } from "@/lib/integrations/routes";
import type { DiscoveredCert } from "@/types/discovery";
import type { CredentialRecord, CredentialProvider } from "@/types/ssl";

/**
 * The only targets the agent really discovers (agent DiscoveryAdapterFactory:
 * AwsAcmDiscoveryAdapter, AwsOrganizationDiscoveryAdapter,
 * AzureKvDiscoveryAdapter, KubernetesDiscoveryAdapter). Azure App Gateway,
 * Front Door, AGC, GCP, and the separate AWS ALB, NLB, CloudFront and API
 * Gateway types are not offered: the server rejects them with 400.
 */
export const DISCOVERY_SOURCE_OPTIONS = [
  { value: "AWS_ORGANIZATION", label: "AWS Organization ACM" },
  { value: "AWS_ACM", label: "AWS ACM (region)" },
  { value: "AZURE_KV", label: "Azure Key Vault" },
  { value: "KUBERNETES_SECRETS", label: "Kubernetes Secrets" },
] as const;

/** Shown where discovery targets are picked, so ALB and friends are not missed. */
export const AWS_ACM_DISCOVERY_COVERAGE_HELP =
  "AWS ACM discovery covers certificates attached to ALB, NLB, CloudFront and API Gateway.";

export const DISCOVERY_SUPPORTED_TARGET_TYPES: ReadonlySet<string> = new Set(
  DISCOVERY_SOURCE_OPTIONS.map((option) => option.value),
);

/** True when the agent can discover this target type. */
export function isDiscoverableTargetType(
  targetType: string | null | undefined,
): boolean {
  return DISCOVERY_SUPPORTED_TARGET_TYPES.has(
    (targetType ?? "").trim().toUpperCase(),
  );
}

export type DiscoveryBadgeVariant = NonNullable<BadgeProps["variant"]>;

export function credentialDetailHref(credentialXref: string): string {
  return deploymentTargetDetailsHref(credentialXref);
}

export function formatDiscoveryTargetLabel(
  targetType: string | null | undefined,
): string {
  return formatProviderLabel(targetType ?? undefined);
}

export function getCertStatusBadgeVariant(
  status: string | null,
): DiscoveryBadgeVariant {
  switch ((status ?? "").toUpperCase()) {
    case "ISSUED":
      return "success";
    case "EXPIRED":
    case "REVOKED":
      return "destructive";
    case "PENDING_VALIDATION":
      return "warning";
    case "INACTIVE":
    default:
      return "secondary";
  }
}

export function getManagedLabel(managed: boolean | null): string {
  if (managed === true) return "Managed";
  if (managed === false) return "Unmanaged";
  return "Unknown";
}

export function getManagedBadgeVariant(
  managed: boolean | null,
): DiscoveryBadgeVariant {
  if (managed === true) return "success";
  return "secondary";
}

/**
 * Unmanaged the way the server counts it (ValueSummaryService): managed is
 * false and the certificate was not marked MISSING by the latest scan.
 */
export function isUnmanagedDiscoveredCert(
  cert: Pick<DiscoveredCert, "managed" | "inventoryStatus">,
): boolean {
  return cert.managed === false && cert.inventoryStatus !== "MISSING";
}

export function isExpiredAt(dateValue: string | null): boolean {
  return Boolean(dateValue && new Date(dateValue) < new Date());
}

export function isExpiringWithinDays(
  dateValue: string | null,
  days: number,
): boolean {
  if (!dateValue) return false;
  const expiry = new Date(dateValue).getTime();
  const now = Date.now();
  const windowMs = days * 24 * 60 * 60 * 1000;
  return expiry >= now && expiry <= now + windowMs;
}

export function getExpiryBadgeVariant(
  dateValue: string | null,
): DiscoveryBadgeVariant {
  if (isExpiredAt(dateValue)) return "destructive";
  if (isExpiringWithinDays(dateValue, 30)) return "warning";
  return "default";
}

export function getExpiryTextVariant(dateValue: string | null) {
  if (isExpiredAt(dateValue)) return "destructive";
  if (isExpiringWithinDays(dateValue, 30)) return "warning";
  return "foreground";
}

export function credentialDisplayLabel(credential: CredentialRecord): string {
  return (
    credential.description ||
    credential.alias ||
    credential.credentialXref ||
    "Unknown credential"
  );
}

export function credentialSubLabel(credential: CredentialRecord): string {
  const parts: string[] = [];
  if (credential.providerDisplayName)
    parts.push(credential.providerDisplayName);
  if (credential.targetType)
    parts.push(formatDiscoveryTargetLabel(credential.targetType));
  return parts.join(" - ");
}

export function credentialServiceApiValue(
  credential: CredentialRecord,
): string {
  return (
    credential.targetType ??
    credential.providerName ??
    credential.provider ??
    ""
  );
}

export function credentialProviderKey(
  credential: CredentialRecord,
): CredentialProvider {
  return (
    resolveCredentialProviderFromApiValue(
      credentialServiceApiValue(credential),
    ) ||
    credential.provider ||
    "aws"
  );
}
