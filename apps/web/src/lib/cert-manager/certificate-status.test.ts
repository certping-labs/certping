// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  isIssuanceFailedCertificateStatus,
  CERTIFICATE_STATUS_FILTER_OPTIONS,
  ENDED_CERTIFICATE_STATUSES,
  FAILED_CERTIFICATE_STATUSES,
  NEEDS_ACTION_CERTIFICATE_STATUSES,
  PENDING_CERTIFICATE_STATUSES,
  SERVING_CERTIFICATE_STATUSES,
  getCertificateStatusGroup,
  getCertificateStatusLabel,
  getCertificateStatusTone,
  isEndedCertificateStatus,
  isFailedCertificateStatus,
  isInFlightCertificateStatus,
  isNeedsActionCertificateStatus,
  isPendingCertificateStatus,
  isServingCertificateStatus,
  normalizeCertificateStatus,
} from "@/lib/cert-manager/certificate-status";

const BACKEND_STATUSES = [
  "PENDING",
  "ACTIVE",
  "RENEW_SUCCESS",
  "RENEWAL_FAILED",
  "FAILED",
  "EXPIRED",
  "RENEWING",
  "REVOKING",
  "REVOKED",
  "REVOCATION_FAILED",
  "DELETED",
  "PENDING_DNS",
  "AWAITING_DNS",
  "VALIDATING",
  "CANCELLED_MANUAL",
];

describe("certificate-status", () => {
  it("places every backend status in exactly one group", () => {
    const sets = [
      PENDING_CERTIFICATE_STATUSES,
      NEEDS_ACTION_CERTIFICATE_STATUSES,
      FAILED_CERTIFICATE_STATUSES,
      SERVING_CERTIFICATE_STATUSES,
      ENDED_CERTIFICATE_STATUSES,
    ];
    for (const status of BACKEND_STATUSES) {
      expect(sets.filter((set) => set.has(status))).toHaveLength(1);
      expect(getCertificateStatusGroup(status)).not.toBe("unknown");
    }
    expect(sets.reduce((total, set) => total + set.size, 0)).toBe(
      BACKEND_STATUSES.length,
    );
  });

  it.each(["ISSUING", "DEPLOYING", "", null, undefined])(
    "treats %p as an unknown certificate status",
    (status) => {
      expect(getCertificateStatusGroup(status)).toBe("unknown");
      expect(getCertificateStatusTone(status)).toBe("secondary");
    },
  );

  it("normalizes casing and whitespace before matching", () => {
    expect(normalizeCertificateStatus(" awaiting_dns ")).toBe("AWAITING_DNS");
    expect(isPendingCertificateStatus(" pending_dns ")).toBe(true);
    expect(isNeedsActionCertificateStatus("awaiting_dns")).toBe(true);
    expect(isFailedCertificateStatus("renewal_failed")).toBe(true);
    expect(isServingCertificateStatus("revocation_failed")).toBe(true);
    expect(isEndedCertificateStatus("cancelled_manual")).toBe(true);
    expect(isServingCertificateStatus("expired")).toBe(false);
  });

  it("treats pending work and revocation as in flight, but not a wait on the user", () => {
    expect(isInFlightCertificateStatus("PENDING_DNS")).toBe(true);
    expect(isInFlightCertificateStatus("REVOKING")).toBe(true);
    expect(isInFlightCertificateStatus("AWAITING_DNS")).toBe(false);
    expect(isInFlightCertificateStatus("ACTIVE")).toBe(false);
  });

  it("labels statuses in sentence case", () => {
    expect(getCertificateStatusLabel("AWAITING_DNS")).toBe(
      "Awaiting DNS records",
    );
    expect(getCertificateStatusLabel("PENDING_DNS")).toBe(
      "Preparing DNS records",
    );
    expect(getCertificateStatusLabel("cancelled_manual")).toBe("Cancelled");
    expect(getCertificateStatusLabel("SOMETHING_NEW")).toBe("Something new");
    expect(getCertificateStatusLabel(undefined)).toBe("Unknown");
  });

  it("maps statuses to badge tones", () => {
    expect(getCertificateStatusTone("ACTIVE")).toBe("success");
    expect(getCertificateStatusTone("RENEW_SUCCESS")).toBe("success");
    expect(getCertificateStatusTone("REVOKING")).toBe("warning");
    expect(getCertificateStatusTone("AWAITING_DNS")).toBe("warning");
    expect(getCertificateStatusTone("PENDING_DNS")).toBe("warning");
    expect(getCertificateStatusTone("FAILED")).toBe("destructive");
    expect(getCertificateStatusTone("EXPIRED")).toBe("destructive");
    expect(getCertificateStatusTone("REVOKED")).toBe("destructive");
    expect(getCertificateStatusTone("DELETED")).toBe("secondary");
  });

  it("offers only real list statuses as filters", () => {
    const values = CERTIFICATE_STATUS_FILTER_OPTIONS.map(
      (option) => option.value,
    );
    expect(values).toContain("PENDING_DNS");
    expect(values).toContain("AWAITING_DNS");
    expect(values).not.toContain("ISSUING");
    expect(values).not.toContain("DEPLOYING");
    expect(
      CERTIFICATE_STATUS_FILTER_OPTIONS.find(
        (option) => option.value === "AWAITING_DNS",
      )?.label,
    ).toBe("Awaiting DNS records");
    expect(
      CERTIFICATE_STATUS_FILTER_OPTIONS.find(
        (option) => option.value === "RENEWAL_FAILED",
      )?.label,
    ).toBe("Renewal failed");
  });

  it("treats only FAILED as a failed issuance", () => {
    expect(isIssuanceFailedCertificateStatus(" failed ")).toBe(true);
    expect(isIssuanceFailedCertificateStatus("RENEWAL_FAILED")).toBe(false);
    expect(isIssuanceFailedCertificateStatus(null)).toBe(false);
  });
});
