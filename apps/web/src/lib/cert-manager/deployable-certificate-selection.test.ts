// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  getLifecycleHistoryIdsToResolve,
  getDeployableCertificates,
  isDeployableCertificateStatus,
  resolveDeployableCertificateXref,
} from "@/lib/cert-manager/deployable-certificate-selection";
import type { SSLCertificateListItem } from "@/types/ssl";

const certificate = (
  overrides: Partial<SSLCertificateListItem>,
): SSLCertificateListItem => ({
  domain: "app.example.org",
  status: "ACTIVE",
  ...overrides,
});

describe("deployable certificate selection", () => {
  it("never offers a customer-held certificate for deployment", () => {
    expect(
      getDeployableCertificates([
        certificate({ certificateXref: "held", keyCustody: "CUSTOMER_HELD" }),
        certificate({ certificateXref: "ours", domain: "ours.example.com" }),
      ]).map((item) => item.certificateXref),
    ).toEqual(["ours"]);
  });

  it("requests lifecycle history only when the current row needs resolution", () => {
    expect(
      getLifecycleHistoryIdsToResolve([
        certificate({ userDomainCertId: "active", status: "ACTIVE" }),
        certificate({ userDomainCertId: "pending", status: "PENDING" }),
        certificate({ userDomainCertId: "pending", status: "RENEWING" }),
        certificate({ userDomainCertId: "renewed", status: "RENEW_SUCCESS" }),
        certificate({ userDomainCertId: "failed", status: "FAILED" }),
        certificate({ userDomainCertId: "revoked", status: "REVOKED" }),
        certificate({ userDomainCertId: "expired", status: "EXPIRED" }),
        certificate({ status: "UNKNOWN" }),
      ]),
    ).toEqual(["pending", "renewed"]);
  });

  it("treats only active and renewing certificates as deployment candidates", () => {
    expect(isDeployableCertificateStatus("ACTIVE")).toBe(true);
    expect(isDeployableCertificateStatus("active")).toBe(true);
    expect(isDeployableCertificateStatus("RENEWING")).toBe(true);
    expect(isDeployableCertificateStatus("RENEW_SUCCESS")).toBe(false);
    expect(isDeployableCertificateStatus("PENDING")).toBe(false);
  });

  it("prefers the active certificate in a lifecycle over pending renewal records", () => {
    const deployableCertificates = getDeployableCertificates([
      certificate({
        certificateXref: "pending-xref",
        status: "PENDING",
        userDomainCertId: "101",
      }),
      certificate({
        certificateXref: "active-xref",
        status: "ACTIVE",
        userDomainCertId: "101",
      }),
    ]);

    expect(deployableCertificates).toHaveLength(1);
    expect(deployableCertificates[0]?.certificateXref).toBe("active-xref");
  });

  it("falls back to the renewing certificate when no active record exists", () => {
    const deployableCertificates = getDeployableCertificates([
      certificate({
        certificateXref: "pending-xref",
        status: "PENDING",
        userDomainCertId: "101",
      }),
      certificate({
        certificateXref: "renewing-xref",
        status: "RENEWING",
        userDomainCertId: "101",
      }),
    ]);

    expect(deployableCertificates).toHaveLength(1);
    expect(deployableCertificates[0]?.certificateXref).toBe("renewing-xref");
  });

  it("uses the current renewing certificate when a pending replacement and renewal-success history exist", () => {
    const deployableCertificates = getDeployableCertificates([
      certificate({
        certificateXref: "cert-629541900320827",
        status: "PENDING",
        userDomainCertId: "101-pending",
      }),
      certificate({
        certificateXref: "cert-629275318339601",
        status: "RENEW_SUCCESS",
        userDomainCertId: "101-history",
      }),
      certificate({
        certificateXref: "cert-629478390362668",
        status: " renewing ",
        userDomainCertId: "101-current",
      }),
    ]);

    expect(deployableCertificates).toHaveLength(1);
    expect(deployableCertificates[0]?.certificateXref).toBe(
      "cert-629478390362668",
    );
  });

  it("resolves a requested pending renewal record to the deployable lifecycle certificate", () => {
    const resolvedXref = resolveDeployableCertificateXref(
      [
        certificate({
          certificateXref: "pending-xref",
          status: "PENDING",
          userDomainCertId: "101",
        }),
        certificate({
          certificateXref: "renewing-xref",
          status: "RENEWING",
          userDomainCertId: "101",
        }),
      ],
      "pending-xref",
    );

    expect(resolvedXref).toBe("renewing-xref");
  });

  it("resolves pending or renewal-success lifecycle xrefs to the current renewing xref", () => {
    const lifecycleCertificates = [
      certificate({
        certificateXref: "cert-629541900320827",
        status: "PENDING",
        userDomainCertId: "101-pending",
      }),
      certificate({
        certificateXref: "cert-629275318339601",
        status: "RENEW_SUCCESS",
        userDomainCertId: "101-history",
      }),
      certificate({
        certificateXref: "cert-629478390362668",
        status: "RENEWING",
        userDomainCertId: "101-current",
      }),
    ];

    expect(
      resolveDeployableCertificateXref(
        lifecycleCertificates,
        "cert-629541900320827",
      ),
    ).toBe("cert-629478390362668");
    expect(
      resolveDeployableCertificateXref(
        lifecycleCertificates,
        "cert-629275318339601",
      ),
    ).toBe("cert-629478390362668");
  });

  it("does not expose renewal-success when no active or renewing record exists", () => {
    expect(
      getDeployableCertificates([
        certificate({
          certificateXref: "pending-xref",
          status: "PENDING",
          userDomainCertId: "101-pending",
        }),
        certificate({
          certificateXref: "renew-success-xref",
          status: "RENEW_SUCCESS",
          userDomainCertId: "101-history",
        }),
      ]),
    ).toEqual([]);
  });

  it("groups domainless certificates by lifecycle identity", () => {
    const deployableCertificates = getDeployableCertificates([
      certificate({
        certificateXref: "active-by-udc",
        domain: "",
        status: "ACTIVE",
        userDomainCertId: "101",
      }),
      certificate({
        certificateXref: "active-by-xref",
        domain: "",
        status: "ACTIVE",
        userDomainCertId: undefined,
      }),
      certificate({
        certificateXref: undefined,
        domain: "",
        status: "ACTIVE",
        userDomainCertId: undefined,
      }),
    ]);

    expect(deployableCertificates.map((item) => item.certificateXref)).toEqual([
      "active-by-udc",
      "active-by-xref",
    ]);
  });

  it("returns no certificate when the requested lifecycle row is absent", () => {
    expect(
      resolveDeployableCertificateXref(
        [certificate({ certificateXref: "active-xref" })],
        "missing-xref",
      ),
    ).toBeUndefined();
  });

  it("resolves a requested lifecycle row by user-domain certificate id", () => {
    const resolvedXref = resolveDeployableCertificateXref(
      [
        certificate({
          certificateXref: "pending-xref",
          status: "PENDING",
          userDomainCertId: "101-pending",
        }),
        certificate({
          certificateXref: "renewing-xref",
          status: "RENEWING",
          userDomainCertId: "101-current",
        }),
      ],
      "101-pending",
    );

    expect(resolvedXref).toBe("renewing-xref");
  });
});
