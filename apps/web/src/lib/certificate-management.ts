// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getSanGroupingKey } from "@/lib/cert-manager/san-domain-helpers";
import type { CertificateManagementState } from "@/types/cert-manager";

interface CertificateManagementSnapshot {
  dnsConfigXref?: string | Record<string, string>;
  deploymentCredentialXrefs?: string[];
  status?: string;
}

export function getPrimaryDnsConfigXref(
  dnsConfigXref: string | Record<string, string> | null | undefined,
  domain?: string | null,
): string | undefined {
  if (typeof dnsConfigXref === "string") {
    return dnsConfigXref || undefined;
  }

  if (!dnsConfigXref) {
    return undefined;
  }

  const rootXref = domain?.trim()
    ? dnsConfigXref[getSanGroupingKey(domain)]
    : undefined;
  if (typeof rootXref === "string" && rootXref.length > 0) {
    return rootXref;
  }

  return Object.values(dnsConfigXref).find(
    (value): value is string => typeof value === "string" && value.length > 0,
  );
}

export function getCertificateManagementState(
  certificate: CertificateManagementSnapshot,
): CertificateManagementState {
  const hasDnsConfig = Boolean(
    getPrimaryDnsConfigXref(certificate.dnsConfigXref),
  );
  const hasDeploymentTargets =
    (certificate.deploymentCredentialXrefs || []).length > 0;

  if (hasDnsConfig && hasDeploymentTargets) {
    return "fully-managed";
  }

  if (hasDnsConfig) {
    return "dns-managed";
  }

  if (hasDeploymentTargets) {
    return "deployment-managed";
  }

  return "manual";
}

export function isCertificateManaged(
  certificate: CertificateManagementSnapshot,
): boolean {
  return getCertificateManagementState(certificate) !== "manual";
}

export function getCertificateManagementLabel(
  state: CertificateManagementState,
): string {
  switch (state) {
    case "dns-managed":
      return "DNS managed";
    case "deployment-managed":
      return "Deployment managed";
    case "fully-managed":
      return "Fully managed";
    default:
      return "Manual";
  }
}

export function getCertificateManagementDescription(
  state: CertificateManagementState,
): string {
  switch (state) {
    case "dns-managed":
      return "Auto-renew can use a saved DNS credential.";
    case "deployment-managed":
      return "Saved deployment targets are attached to this certificate.";
    case "fully-managed":
      return "This certificate is configured for auto-renew and auto-deploy.";
    default:
      return "No saved DNS or deployment configuration is attached yet.";
  }
}

export function getCertificateManagementBadgeClass(
  state: CertificateManagementState,
): string {
  switch (state) {
    case "fully-managed":
      return "status-success";
    case "dns-managed":
      return "status-info";
    case "deployment-managed":
      return "status-info";
    default:
      return "status-warning";
  }
}

export function canConvertManualCertificateToAutomated(
  certificate: CertificateManagementSnapshot,
): boolean {
  return (
    !certificate.dnsConfigXref &&
    (certificate.status || "").toUpperCase() === "ACTIVE"
  );
}
