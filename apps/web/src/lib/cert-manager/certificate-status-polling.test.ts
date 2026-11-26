// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  createCertificateStatusUpdate,
  getCertificatePollingIdentifier,
  getCertificatesRequiringStatusPolling,
  mergeCertificateStatusUpdates,
  selectCertificateStatusUpdate,
  shouldPollCertificateStatus,
} from "@/lib/cert-manager/certificate-status-polling";
import type { ManagedCertificateSummary } from "@/types/cert-manager";
import type { SSLCertificateListItem } from "@/types/ssl";

const certificate = (
  overrides: Partial<SSLCertificateListItem> = {},
): SSLCertificateListItem => ({
  certificateXref: "cert-1",
  userDomainCertId: "udc-1",
  domain: "app.example.com",
  status: "PENDING",
  ...overrides,
});

const summary = (
  overrides: Partial<ManagedCertificateSummary> = {},
): ManagedCertificateSummary => ({
  certificateXref: "cert-1",
  userDomainCertId: "udc-1",
  domain: "app.example.com",
  status: "ACTIVE",
  rawStatus: "ACTIVE",
  ...overrides,
});

describe("certificate status polling", () => {
  it.each(["PENDING", " pending_dns ", "VALIDATING", "RENEWING", "REVOKING"])(
    "polls transitional status %s",
    (status) => {
      expect(shouldPollCertificateStatus(status)).toBe(true);
    },
  );

  it.each([
    "ACTIVE",
    "FAILED",
    "EXPIRED",
    "AWAITING_DNS",
    "ISSUING",
    "DEPLOYING",
    null,
    undefined,
  ])("does not poll terminal, user-blocked or unknown status %s", (status) => {
    expect(shouldPollCertificateStatus(status)).toBe(false);
  });

  it("selects only transitional certificates with a usable domain", () => {
    expect(
      getCertificatesRequiringStatusPolling([
        certificate(),
        certificate({ certificateXref: "cert-2", status: "ACTIVE" }),
        certificate({ certificateXref: "cert-3", domain: " " }),
        certificate({
          certificateXref: "cert-4",
          domain: null as unknown as string,
        }),
      ]),
    ).toEqual([certificate()]);
  });

  it("builds stable identifiers from the best available identity", () => {
    expect(getCertificatePollingIdentifier(certificate())).toBe("udc:udc-1");
    expect(
      getCertificatePollingIdentifier(
        certificate({ userDomainCertId: undefined }),
      ),
    ).toBe("xref:cert-1");
    expect(
      getCertificatePollingIdentifier(
        certificate({
          certificateXref: undefined,
          userDomainCertId: undefined,
        }),
      ),
    ).toBe("domain:app.example.com");
    expect(
      getCertificatePollingIdentifier(
        certificate({
          certificateXref: undefined,
          domain: null as unknown as string,
          userDomainCertId: undefined,
        }),
      ),
    ).toBe("domain:");
  });

  it("prefers lifecycle id, then xref, then exact domain for status updates", () => {
    expect(
      selectCertificateStatusUpdate(certificate(), [
        summary({ certificateXref: "other", userDomainCertId: "udc-1" }),
      ])?.status,
    ).toBe("ACTIVE");
    expect(
      selectCertificateStatusUpdate(certificate(), [
        summary({ certificateXref: "other", userDomainCertId: "other" }),
      ]),
    ).toBeUndefined();
    expect(
      selectCertificateStatusUpdate(
        certificate({ userDomainCertId: undefined }),
        [summary({ userDomainCertId: "other" })],
      )?.status,
    ).toBe("ACTIVE");
    expect(
      selectCertificateStatusUpdate(
        certificate({
          certificateXref: undefined,
          userDomainCertId: undefined,
        }),
        [summary({ certificateXref: "other", userDomainCertId: "other" })],
      )?.status,
    ).toBe("ACTIVE");
    expect(
      selectCertificateStatusUpdate(
        certificate({
          certificateXref: undefined,
          domain: null as unknown as string,
          userDomainCertId: undefined,
        }),
        [
          summary({
            certificateXref: "other",
            domain: null as unknown as string,
            userDomainCertId: "other",
          }),
        ],
      ),
    ).toBeUndefined();
    expect(selectCertificateStatusUpdate(certificate(), [])).toBeUndefined();
  });

  it("falls back to the original xref when a lifecycle id changes", () => {
    expect(
      selectCertificateStatusUpdate(certificate(), [
        summary({ userDomainCertId: "udc-2" }),
      ])?.userDomainCertId,
    ).toBe("udc-2");
  });

  it("does not fall back to a shared domain when stable identities differ", () => {
    expect(
      selectCertificateStatusUpdate(certificate(), [
        summary({
          certificateXref: "other-xref",
          userDomainCertId: "other-udc",
        }),
      ]),
    ).toBeUndefined();
  });

  it("merges targeted updates without dropping unaffected list rows", () => {
    const active = certificate({ status: "ACTIVE" });
    const unaffected = certificate({
      certificateXref: "cert-2",
      domain: "other.example.com",
      status: "ACTIVE",
      userDomainCertId: "udc-2",
    });

    expect(
      mergeCertificateStatusUpdates(
        [certificate(), unaffected],
        [createCertificateStatusUpdate(certificate(), active)],
      ),
    ).toEqual([active, unaffected]);
    expect(mergeCertificateStatusUpdates([unaffected], [])).toEqual([
      unaffected,
    ]);
  });

  it("preserves the original row identity when an update gains a lifecycle id", () => {
    const original = certificate({ userDomainCertId: undefined });
    const active = certificate({
      status: "ACTIVE",
      userDomainCertId: "new-udc",
    });

    expect(
      mergeCertificateStatusUpdates(
        [original],
        [createCertificateStatusUpdate(original, active)],
      ),
    ).toEqual([active]);
  });
});
