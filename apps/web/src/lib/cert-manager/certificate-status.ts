// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export type CertificateStatusGroup =
  "pending" | "needs-action" | "failed" | "serving" | "ended" | "unknown";

export type CertificateStatusTone =
  "success" | "warning" | "destructive" | "secondary";

export const PENDING_CERTIFICATE_STATUSES: ReadonlySet<string> = new Set([
  "PENDING",
  "PENDING_DNS",
  "VALIDATING",
  "RENEWING",
]);

export const NEEDS_ACTION_CERTIFICATE_STATUSES: ReadonlySet<string> = new Set([
  "AWAITING_DNS",
]);

export const FAILED_CERTIFICATE_STATUSES: ReadonlySet<string> = new Set([
  "FAILED",
  "RENEWAL_FAILED",
]);

export const SERVING_CERTIFICATE_STATUSES: ReadonlySet<string> = new Set([
  "ACTIVE",
  "RENEW_SUCCESS",
  "REVOKING",
  "REVOCATION_FAILED",
]);

export const ENDED_CERTIFICATE_STATUSES: ReadonlySet<string> = new Set([
  "EXPIRED",
  "REVOKED",
  "DELETED",
  "CANCELLED_MANUAL",
]);

const IN_FLIGHT_CERTIFICATE_STATUSES: ReadonlySet<string> = new Set([
  ...PENDING_CERTIFICATE_STATUSES,
  "REVOKING",
]);

const CERTIFICATE_STATUS_LABELS: Readonly<Record<string, string>> = {
  ACTIVE: "Active",
  PENDING: "Pending",
  PENDING_DNS: "Preparing DNS records",
  AWAITING_DNS: "Awaiting DNS records",
  VALIDATING: "Validating",
  RENEWING: "Renewing",
  RENEW_SUCCESS: "Renewed",
  RENEWAL_FAILED: "Renewal failed",
  FAILED: "Failed",
  EXPIRED: "Expired",
  REVOKING: "Revoking",
  REVOKED: "Revoked",
  REVOCATION_FAILED: "Revocation failed",
  DELETED: "Deleted",
  CANCELLED_MANUAL: "Cancelled",
};

export const CERTIFICATE_STATUS_FILTER_OPTIONS: ReadonlyArray<{
  readonly label: string;
  readonly value: string;
}> = [
  "ACTIVE",
  "PENDING",
  "PENDING_DNS",
  "AWAITING_DNS",
  "VALIDATING",
  "RENEWING",
  "FAILED",
  "RENEWAL_FAILED",
  "REVOKING",
  "REVOCATION_FAILED",
  "REVOKED",
  "EXPIRED",
].map((value) => ({ value, label: CERTIFICATE_STATUS_LABELS[value] }));

export const normalizeCertificateStatus = (
  status: string | null | undefined,
): string => status?.trim().toUpperCase() ?? "";

export const isPendingCertificateStatus = (
  status: string | null | undefined,
): boolean =>
  PENDING_CERTIFICATE_STATUSES.has(normalizeCertificateStatus(status));

/** The certificate never issued; a failed renewal of a live one is not this. */
export const isIssuanceFailedCertificateStatus = (
  status: string | null | undefined,
): boolean => normalizeCertificateStatus(status) === "FAILED";

export const isNeedsActionCertificateStatus = (
  status: string | null | undefined,
): boolean =>
  NEEDS_ACTION_CERTIFICATE_STATUSES.has(normalizeCertificateStatus(status));

export const isFailedCertificateStatus = (
  status: string | null | undefined,
): boolean =>
  FAILED_CERTIFICATE_STATUSES.has(normalizeCertificateStatus(status));

export const isServingCertificateStatus = (
  status: string | null | undefined,
): boolean =>
  SERVING_CERTIFICATE_STATUSES.has(normalizeCertificateStatus(status));

export const isEndedCertificateStatus = (
  status: string | null | undefined,
): boolean =>
  ENDED_CERTIFICATE_STATUSES.has(normalizeCertificateStatus(status));

export const isInFlightCertificateStatus = (
  status: string | null | undefined,
): boolean =>
  IN_FLIGHT_CERTIFICATE_STATUSES.has(normalizeCertificateStatus(status));

export function getCertificateStatusGroup(
  status: string | null | undefined,
): CertificateStatusGroup {
  const normalized = normalizeCertificateStatus(status);
  if (PENDING_CERTIFICATE_STATUSES.has(normalized)) return "pending";
  if (NEEDS_ACTION_CERTIFICATE_STATUSES.has(normalized)) return "needs-action";
  if (FAILED_CERTIFICATE_STATUSES.has(normalized)) return "failed";
  if (SERVING_CERTIFICATE_STATUSES.has(normalized)) return "serving";
  if (ENDED_CERTIFICATE_STATUSES.has(normalized)) return "ended";
  return "unknown";
}

export function getCertificateStatusLabel(
  status: string | null | undefined,
): string {
  const normalized = normalizeCertificateStatus(status);
  const label = CERTIFICATE_STATUS_LABELS[normalized];
  if (label) return label;
  const words = normalized.toLowerCase().replace(/_/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Unknown";
}

export function getCertificateStatusTone(
  status: string | null | undefined,
): CertificateStatusTone {
  const normalized = normalizeCertificateStatus(status);
  if (normalized === "ACTIVE" || normalized === "RENEW_SUCCESS") {
    return "success";
  }
  if (normalized === "EXPIRED" || normalized === "REVOKED") {
    return "destructive";
  }
  switch (getCertificateStatusGroup(normalized)) {
    case "pending":
    case "needs-action":
    case "serving":
      return "warning";
    case "failed":
      return "destructive";
    default:
      return "secondary";
  }
}
