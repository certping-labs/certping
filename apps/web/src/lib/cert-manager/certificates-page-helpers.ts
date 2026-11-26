// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { KeyCustody } from "@/types/ssl";
import { isCustomerHeldKey } from "@/lib/cert-manager/key-custody";
import type { SSLCertificateListItem } from "@/types/ssl";
import type { CertificateManagementState } from "@/types/cert-manager";
import { canConvertManualCertificateToAutomated } from "@/lib/certificate-management";
import { isDeployableCertificateStatus } from "@/lib/cert-manager/deployable-certificate-selection";
import {
  getCertificateStatusLabel,
  getCertificateStatusTone,
  isInFlightCertificateStatus,
  isNeedsActionCertificateStatus,
  type CertificateStatusTone,
} from "@/lib/cert-manager/certificate-status";
import { getRemainingDays } from "@/lib/utils";

export type CertificateBadgeVariant = CertificateStatusTone;

interface CertificateActionSnapshot {
  certificateXref?: string;
  domain?: string;
  managementState?: CertificateManagementState;
  status: string;
  userDomainCertId?: string | number;
  keyCustody?: KeyCustody;
}

const ACTIVE_LIKE_CERTIFICATE_STATUSES = new Set(["ACTIVE", "RENEW_SUCCESS"]);

const getNormalizedCertificateStatus = (status: string): string =>
  status.trim().toUpperCase();

export function isActiveLikeCertificateStatus(status: string): boolean {
  return ACTIVE_LIKE_CERTIFICATE_STATUSES.has(
    getNormalizedCertificateStatus(status),
  );
}

export function formatCertificateStatusLabel(value: string): string {
  return getCertificateStatusLabel(value);
}

export function getCertificateStatusBadgeVariant(
  status: string,
): CertificateBadgeVariant {
  return getCertificateStatusTone(status);
}

export function getCoverageSummary(
  certificate: SSLCertificateListItem,
): string[] {
  if (isActiveLikeCertificateStatus(certificate.status)) {
    return ["Ready"];
  }
  if (isNeedsActionCertificateStatus(certificate.status)) {
    return ["Action needed"];
  }
  if (isInFlightCertificateStatus(certificate.status)) {
    return ["In progress"];
  }
  return [];
}

export function getManagementSummary(
  certificate: SSLCertificateListItem,
): string {
  const state = certificate.managementState || "manual";
  const deploymentTargets = certificate.deploymentCredentialXrefs || [];

  const dnsConfigXrefUnknown = (
    certificate as SSLCertificateListItem & {
      dnsConfigXref?: string | Record<string, string>;
      dnsCredentialKvPath?: string;
    }
  ).dnsConfigXref;
  const dnsCredentialKvPath = (
    certificate as SSLCertificateListItem & {
      dnsCredentialKvPath?: string;
    }
  ).dnsCredentialKvPath;
  const dnsConfigCount =
    typeof dnsConfigXrefUnknown === "string"
      ? dnsConfigXrefUnknown.trim().length > 0
        ? 1
        : 0
      : dnsConfigXrefUnknown
        ? Object.keys(dnsConfigXrefUnknown).length
        : 0;
  const hasDnsCredential =
    dnsConfigCount > 0 || Boolean(dnsCredentialKvPath?.trim());

  if (state === "fully-managed") {
    return `DNS + ${deploymentTargets.length} deployment target${
      deploymentTargets.length === 1 ? "" : "s"
    }`;
  }

  if (state === "dns-managed") {
    return "Saved DNS credential attached";
  }

  if (state === "deployment-managed") {
    return `${deploymentTargets.length} deployment target${
      deploymentTargets.length === 1 ? "" : "s"
    } attached`;
  }

  if (hasDnsCredential && deploymentTargets.length > 0) {
    return `DNS + ${deploymentTargets.length} deployment target${
      deploymentTargets.length === 1 ? "" : "s"
    } attached`;
  }

  if (hasDnsCredential) {
    return "Saved DNS credential attached";
  }

  if (deploymentTargets.length > 0) {
    return `${deploymentTargets.length} deployment target${
      deploymentTargets.length === 1 ? "" : "s"
    } attached`;
  }

  return "No saved DNS or deployment config";
}

export function canDeleteCertificateRecord(
  certificate: CertificateActionSnapshot,
): boolean {
  if (!certificate.userDomainCertId) {
    return false;
  }

  return [
    "PENDING",
    "PENDING_DNS",
    "AWAITING_DNS",
    "FAILED",
    "REVOKED",
    "EXPIRED",
  ].includes(certificate.status.toUpperCase());
}

export function canRevokeCertificateRecord(
  certificate: CertificateActionSnapshot,
): boolean {
  return getNormalizedCertificateStatus(certificate.status) === "ACTIVE";
}

export function canRenewCertificateRecord(
  certificate: CertificateActionSnapshot,
): boolean {
  return (
    getNormalizedCertificateStatus(certificate.status) === "ACTIVE" &&
    !isCustomerHeldKey(certificate)
  );
}

/** A live customer-held certificate: CertPing cannot renew it, the customer requests again. */
export function canRequestCertificateAgain(
  certificate: CertificateActionSnapshot,
): boolean {
  return (
    getNormalizedCertificateStatus(certificate.status) === "ACTIVE" &&
    isCustomerHeldKey(certificate)
  );
}

export function canDeployCertificateRecord(
  certificate: CertificateActionSnapshot,
): boolean {
  return (
    isDeployableCertificateStatus(certificate.status) &&
    !isCustomerHeldKey(certificate)
  );
}

export function canManageManualDns(
  certificate: CertificateActionSnapshot,
): boolean {
  if (!certificate.certificateXref) {
    return false;
  }

  if ((certificate.managementState ?? "manual") !== "manual") {
    return false;
  }

  return ["AWAITING_DNS", "VALIDATING", "VALIDATION"].includes(
    certificate.status.toUpperCase(),
  );
}

export function canConfigureCertificateAutomation(
  certificate: CertificateActionSnapshot,
): boolean {
  return (
    isDeployableCertificateStatus(certificate.status) &&
    !isCustomerHeldKey(certificate) &&
    Boolean(certificate.certificateXref || certificate.domain)
  );
}

export function getAutomationActionLabel(
  certificate: SSLCertificateListItem,
): string {
  return canConvertManualCertificateToAutomated(certificate)
    ? "Enable automation"
    : "Manage automation";
}

export function getCertificateDetailHref(
  certificate: SSLCertificateListItem,
): string {
  return `/cert-manager/manage/${encodeURIComponent(
    certificate.certificateXref || certificate.domain,
  )}`;
}

export function canViewCertificateDetails(
  certificate: SSLCertificateListItem,
): boolean {
  return Boolean(certificate.certificateXref || certificate.domain);
}

export type CertificateRenewalBucket = "healthy" | "expiring_30_days" | "other";

export function getCertificateRenewalBucket(
  certificate: SSLCertificateListItem,
): CertificateRenewalBucket {
  const remainingDays = getRemainingDays(certificate.validTo ?? null);
  if (remainingDays === null || certificate.status !== "ACTIVE") {
    return "other";
  }
  if (remainingDays > 0 && remainingDays <= 30) {
    return "expiring_30_days";
  }
  return "healthy";
}
