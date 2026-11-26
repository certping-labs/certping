// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canConfigureCertificateAutomation,
  canDeleteCertificateRecord,
  canDeployCertificateRecord,
  canManageManualDns,
  canRenewCertificateRecord,
  canRequestCertificateAgain,
  canRevokeCertificateRecord,
  canViewCertificateDetails,
  formatCertificateStatusLabel,
  getAutomationActionLabel,
  getCertificateDetailHref,
  getCertificateRenewalBucket,
  getCertificateStatusBadgeVariant,
  getCoverageSummary,
  getManagementSummary,
  isActiveLikeCertificateStatus,
} from "@/lib/cert-manager/certificates-page-helpers";
import type { SSLCertificateListItem } from "@/types/ssl";

function makeCertificate(
  overrides: Partial<SSLCertificateListItem>,
): SSLCertificateListItem {
  return overrides as SSLCertificateListItem;
}

describe("certificates-page-helpers", () => {
  describe("a customer-held key", () => {
    const customerHeld = makeCertificate({
      certificateXref: "xref-c",
      domain: "held.example.com",
      status: "ACTIVE",
      keyCustody: "CUSTOMER_HELD",
    });

    it("is requested again rather than renewed or deployed by CertPing", () => {
      expect(canRenewCertificateRecord(customerHeld)).toBe(false);
      expect(canDeployCertificateRecord(customerHeld)).toBe(false);
      expect(canConfigureCertificateAutomation(customerHeld)).toBe(false);
      expect(canRequestCertificateAgain(customerHeld)).toBe(true);
      expect(canRevokeCertificateRecord(customerHeld)).toBe(true);
    });

    it("is not offered again while it is not active", () => {
      expect(
        canRequestCertificateAgain({ ...customerHeld, status: "EXPIRED" }),
      ).toBe(false);
    });

    it("leaves a platform-held certificate as before", () => {
      const platformHeld = makeCertificate({
        ...customerHeld,
        keyCustody: "PLATFORM_HELD",
      });
      expect(canRenewCertificateRecord(platformHeld)).toBe(true);
      expect(canDeployCertificateRecord(platformHeld)).toBe(true);
      expect(canRequestCertificateAgain(platformHeld)).toBe(false);
    });
  });

  describe("formatCertificateStatusLabel", () => {
    it("formats statuses into sentence-case labels", () => {
      expect(formatCertificateStatusLabel("AWAITING_DNS")).toBe(
        "Awaiting DNS records",
      );
      expect(formatCertificateStatusLabel("PENDING_DNS")).toBe(
        "Preparing DNS records",
      );
      expect(formatCertificateStatusLabel("REVOKED")).toBe("Revoked");
    });
  });

  describe("getCertificateStatusBadgeVariant", () => {
    it("maps status groups into UI variants", () => {
      expect(getCertificateStatusBadgeVariant("ACTIVE")).toBe("success");
      expect(getCertificateStatusBadgeVariant("RENEW_SUCCESS")).toBe("success");

      expect(getCertificateStatusBadgeVariant("PENDING")).toBe("warning");
      expect(getCertificateStatusBadgeVariant("validating")).toBe("warning");
      expect(getCertificateStatusBadgeVariant("PENDING_DNS")).toBe("warning");
      expect(getCertificateStatusBadgeVariant("AWAITING_DNS")).toBe("warning");
      expect(getCertificateStatusBadgeVariant("RENEWING")).toBe("warning");
      expect(getCertificateStatusBadgeVariant("REVOCATION_FAILED")).toBe(
        "warning",
      );
      expect(getCertificateStatusBadgeVariant("REVOKING")).toBe("warning");

      expect(getCertificateStatusBadgeVariant("FAILED")).toBe("destructive");
      expect(getCertificateStatusBadgeVariant("reVoked")).toBe("destructive");
      expect(getCertificateStatusBadgeVariant("EXPIRED")).toBe("destructive");

      expect(getCertificateStatusBadgeVariant("RENEWAL_FAILED")).toBe(
        "destructive",
      );

      expect(getCertificateStatusBadgeVariant("ISSUING")).toBe("secondary");
      expect(getCertificateStatusBadgeVariant("DEPLOYING")).toBe("secondary");
      expect(getCertificateStatusBadgeVariant("UNKNOWN")).toBe("secondary");
    });
  });

  describe("getCoverageSummary", () => {
    it("returns Ready for ACTIVE, Action needed while DNS records wait on the user, In progress for pending work, else empty", () => {
      expect(getCoverageSummary(makeCertificate({ status: "ACTIVE" }))).toEqual(
        ["Ready"],
      );
      expect(
        getCoverageSummary(makeCertificate({ status: "RENEW_SUCCESS" })),
      ).toEqual(["Ready"]);

      expect(
        getCoverageSummary(makeCertificate({ status: "AWAITING_DNS" })),
      ).toEqual(["Action needed"]);
      expect(
        getCoverageSummary(makeCertificate({ status: "PENDING_DNS" })),
      ).toEqual(["In progress"]);
      expect(
        getCoverageSummary(makeCertificate({ status: "REVOKING" })),
      ).toEqual(["In progress"]);
      expect(
        getCoverageSummary(makeCertificate({ status: "ISSUING" })),
      ).toEqual([]);

      expect(getCoverageSummary(makeCertificate({ status: "FAILED" }))).toEqual(
        [],
      );
    });
  });

  describe("getManagementSummary", () => {
    it("summarizes explicit management states", () => {
      expect(
        getManagementSummary(
          makeCertificate({
            status: "ACTIVE",
            managementState: "fully-managed",
            deploymentCredentialXrefs: ["a"],
          }),
        ),
      ).toBe("DNS + 1 deployment target");

      expect(
        getManagementSummary(
          makeCertificate({
            status: "ACTIVE",
            managementState: "deployment-managed",
            deploymentCredentialXrefs: ["a", "b"],
          }),
        ),
      ).toBe("2 deployment targets attached");

      expect(
        getManagementSummary(
          makeCertificate({
            status: "ACTIVE",
            managementState: "dns-managed",
          }),
        ),
      ).toBe("Saved DNS credential attached");
    });

    it("infers management from DNS/deployment config for manual state", () => {
      expect(
        getManagementSummary(
          makeCertificate({
            status: "ACTIVE",
            managementState: "manual",
            dnsConfigXref: { "a.example": "dns-1" } as unknown as string,
            deploymentCredentialXrefs: ["deploy-1", "deploy-2"],
          } as unknown as Partial<SSLCertificateListItem>),
        ),
      ).toBe("DNS + 2 deployment targets attached");

      expect(
        getManagementSummary(
          makeCertificate({
            status: "ACTIVE",
            managementState: "manual",
            dnsConfigXref: "dns-cred-1",
          }),
        ),
      ).toBe("Saved DNS credential attached");

      expect(
        getManagementSummary(
          makeCertificate({
            status: "ACTIVE",
            managementState: "manual",
            dnsCredentialKvPath: "   https://vault/dns  ",
          } as unknown as Partial<SSLCertificateListItem>),
        ),
      ).toBe("Saved DNS credential attached");

      expect(
        getManagementSummary(
          makeCertificate({
            status: "ACTIVE",
            managementState: "manual",
            deploymentCredentialXrefs: ["deploy-1"],
          }),
        ),
      ).toBe("1 deployment target attached");

      expect(
        getManagementSummary(
          makeCertificate({
            status: "ACTIVE",
            managementState: "manual",
            dnsConfigXref: "",
          }),
        ),
      ).toBe("No saved DNS or deployment config");
    });
  });

  describe("record action gates", () => {
    it("gates delete/revoke/renew/deploy by status", () => {
      expect(
        canDeleteCertificateRecord(
          makeCertificate({ status: "PENDING", userDomainCertId: "101" }),
        ),
      ).toBe(true);
      expect(
        canDeleteCertificateRecord(
          makeCertificate({ status: "PENDING_DNS", userDomainCertId: "101" }),
        ),
      ).toBe(true);
      expect(
        canDeleteCertificateRecord(
          makeCertificate({ status: "AWAITING_DNS", userDomainCertId: "101" }),
        ),
      ).toBe(true);
      expect(
        canDeleteCertificateRecord(
          makeCertificate({ status: "FAILED", userDomainCertId: "101" }),
        ),
      ).toBe(true);
      expect(
        canDeleteCertificateRecord(
          makeCertificate({ status: "REVOKED", userDomainCertId: "101" }),
        ),
      ).toBe(true);
      expect(
        canDeleteCertificateRecord(
          makeCertificate({ status: "EXPIRED", userDomainCertId: "101" }),
        ),
      ).toBe(true);
      expect(
        canDeleteCertificateRecord(
          makeCertificate({ status: "PENDING", userDomainCertId: undefined }),
        ),
      ).toBe(false);
      expect(
        canDeleteCertificateRecord(
          makeCertificate({ status: "ACTIVE", userDomainCertId: "101" }),
        ),
      ).toBe(false);

      expect(
        canRevokeCertificateRecord(makeCertificate({ status: "ACTIVE" })),
      ).toBe(true);
      expect(
        canRenewCertificateRecord(makeCertificate({ status: "ACTIVE" })),
      ).toBe(true);
      expect(
        canDeployCertificateRecord(makeCertificate({ status: "ACTIVE" })),
      ).toBe(true);
      expect(
        canDeployCertificateRecord(makeCertificate({ status: "RENEWING" })),
      ).toBe(true);
      expect(
        canRevokeCertificateRecord(
          makeCertificate({ status: "RENEW_SUCCESS" }),
        ),
      ).toBe(false);
      expect(
        canRenewCertificateRecord(makeCertificate({ status: "RENEW_SUCCESS" })),
      ).toBe(false);
      expect(
        canDeployCertificateRecord(
          makeCertificate({ status: "RENEW_SUCCESS" }),
        ),
      ).toBe(false);
      expect(
        canDeployCertificateRecord(makeCertificate({ status: "PENDING" })),
      ).toBe(false);
      expect(
        canRevokeCertificateRecord(makeCertificate({ status: "FAILED" })),
      ).toBe(false);
    });

    it("recognizes renewal success as an active-like terminal state", () => {
      expect(isActiveLikeCertificateStatus("ACTIVE")).toBe(true);
      expect(isActiveLikeCertificateStatus(" renew_success ")).toBe(true);
      expect(isActiveLikeCertificateStatus("RENEWING")).toBe(false);
    });
  });

  describe("canManageManualDns", () => {
    it("requires xref, manual management, and valid statuses (case-insensitive)", () => {
      expect(
        canManageManualDns(
          makeCertificate({
            certificateXref: "",
            status: "AWAITING_DNS",
            managementState: "manual",
          }),
        ),
      ).toBe(false);

      expect(
        canManageManualDns(
          makeCertificate({
            certificateXref: "cert-1",
            status: "AWAITING_DNS",
            managementState: "dns-managed",
          }),
        ),
      ).toBe(false);

      expect(
        canManageManualDns(
          makeCertificate({
            certificateXref: "cert-1",
            status: "validating",
            managementState: "manual",
          }),
        ),
      ).toBe(true);

      expect(
        canManageManualDns(
          makeCertificate({
            certificateXref: "cert-1",
            status: "FAILED",
            managementState: "manual",
          }),
        ),
      ).toBe(false);
    });
  });

  describe("canConfigureCertificateAutomation", () => {
    it("requires a deployable status and a non-empty identity", () => {
      expect(
        canConfigureCertificateAutomation(
          makeCertificate({
            status: "ACTIVE",
            certificateXref: "cert-1",
          }),
        ),
      ).toBe(true);

      expect(
        canConfigureCertificateAutomation(
          makeCertificate({
            status: "ACTIVE",
            domain: "example.com",
          }),
        ),
      ).toBe(true);

      expect(
        canConfigureCertificateAutomation(
          makeCertificate({
            status: "RENEWING",
            certificateXref: "cert-1",
          }),
        ),
      ).toBe(true);

      expect(
        canConfigureCertificateAutomation(
          makeCertificate({
            status: "PENDING",
            certificateXref: "cert-1",
          }),
        ),
      ).toBe(false);
    });
  });

  describe("getAutomationActionLabel", () => {
    it("returns Enable automation for ACTIVE manual certs without dnsConfigXref, else Manage automation", () => {
      expect(
        getAutomationActionLabel(
          makeCertificate({
            status: "ACTIVE",
            managementState: "manual",
          }),
        ),
      ).toBe("Enable automation");

      expect(
        getAutomationActionLabel(
          makeCertificate({
            status: "ACTIVE",
            dnsConfigXref: "dns-cred-1",
            managementState: "manual",
          }),
        ),
      ).toBe("Manage automation");
    });
  });

  describe("routing helpers", () => {
    it("builds detail href and detail visibility guards", () => {
      expect(
        getCertificateDetailHref(
          makeCertificate({
            certificateXref: "cert/1",
            domain: "example.com",
          }),
        ),
      ).toBe("/cert-manager/manage/cert%2F1");

      expect(
        canViewCertificateDetails(
          makeCertificate({ certificateXref: "cert-1" }),
        ),
      ).toBe(true);
      expect(canViewCertificateDetails(makeCertificate({ domain: "d" }))).toBe(
        true,
      );
      expect(canViewCertificateDetails(makeCertificate({}))).toBe(false);
    });
  });

  describe("getCertificateRenewalBucket", () => {
    it("buckets ACTIVE certificates by remaining days", () => {
      expect(
        getCertificateRenewalBucket(
          makeCertificate({
            status: "ACTIVE",
            validTo: "2026-01-15T00:00:00Z",
          }),
        ),
      ).toBe("expiring_30_days");

      expect(
        getCertificateRenewalBucket(
          makeCertificate({
            status: "ACTIVE",
            validTo: "2026-04-15T00:00:00Z",
          }),
        ),
      ).toBe("healthy");

      expect(
        getCertificateRenewalBucket(
          makeCertificate({
            status: "PENDING",
            validTo: "2026-01-15T00:00:00Z",
          }),
        ),
      ).toBe("other");

      expect(
        getCertificateRenewalBucket(
          makeCertificate({ status: "ACTIVE", validTo: null }),
        ),
      ).toBe("other");
    });
  });
});
