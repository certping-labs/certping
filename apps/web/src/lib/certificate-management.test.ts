// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canConvertManualCertificateToAutomated,
  getCertificateManagementBadgeClass,
  getCertificateManagementDescription,
  getCertificateManagementLabel,
  getPrimaryDnsConfigXref,
  getCertificateManagementState,
  isCertificateManaged,
} from "@/lib/certificate-management";

describe("certificate management helpers", () => {
  it("returns manual when no saved config exists", () => {
    expect(
      getCertificateManagementState({
        dnsConfigXref: undefined,
        deploymentCredentialXrefs: [],
      }),
    ).toBe("manual");
    expect(
      isCertificateManaged({
        dnsConfigXref: undefined,
        deploymentCredentialXrefs: [],
      }),
    ).toBe(false);
  });

  it("returns dns-managed when only dns config exists", () => {
    expect(
      getCertificateManagementState({
        dnsConfigXref: "cred_dns_123",
        deploymentCredentialXrefs: [],
      }),
    ).toBe("dns-managed");
  });

  it("returns deployment-managed when only deployment targets exist", () => {
    expect(
      getCertificateManagementState({
        dnsConfigXref: undefined,
        deploymentCredentialXrefs: ["cred_deploy_1"],
      }),
    ).toBe("deployment-managed");
  });

  it("returns fully-managed when dns and deployment targets exist", () => {
    expect(
      getCertificateManagementState({
        dnsConfigXref: "cred_dns_123",
        deploymentCredentialXrefs: ["cred_deploy_1"],
      }),
    ).toBe("fully-managed");
  });

  it("extracts primary dns config from object map", () => {
    expect(
      getPrimaryDnsConfigXref({
        "example.com": "cred-1",
        "www.example.com": "cred-2",
      }),
    ).toBe("cred-1");
    expect(getPrimaryDnsConfigXref("cred-single")).toBe("cred-single");
    expect(getPrimaryDnsConfigXref(undefined)).toBeUndefined();
  });

  it("picks the credential for the certificate's root domain, not the first entry", () => {
    const dnsConfigXref = {
      "other.io": "cred-other",
      "example.com": "cred-root",
    };
    expect(getPrimaryDnsConfigXref(dnsConfigXref, "*.example.com")).toBe(
      "cred-root",
    );
    expect(getPrimaryDnsConfigXref(dnsConfigXref, "app.example.com")).toBe(
      "cred-root",
    );
    expect(getPrimaryDnsConfigXref(dnsConfigXref, "unmapped.net")).toBe(
      "cred-other",
    );
    expect(getPrimaryDnsConfigXref({}, "example.com")).toBeUndefined();
  });

  it("returns label, description, and badge class per management state", () => {
    expect(getCertificateManagementLabel("manual")).toBe("Manual");
    expect(getCertificateManagementLabel("dns-managed")).toBe("DNS managed");
    expect(getCertificateManagementDescription("deployment-managed")).toContain(
      "deployment targets",
    );
    expect(getCertificateManagementDescription("fully-managed")).toContain(
      "auto-renew",
    );
    expect(getCertificateManagementBadgeClass("manual")).toBe("status-warning");
    expect(getCertificateManagementBadgeClass("dns-managed")).toBe(
      "status-info",
    );
    expect(getCertificateManagementBadgeClass("fully-managed")).toBe(
      "status-success",
    );
  });

  it("allows converting only active manual certs to automated", () => {
    expect(
      canConvertManualCertificateToAutomated({
        dnsConfigXref: undefined,
        status: "ACTIVE",
      }),
    ).toBe(true);
    expect(
      canConvertManualCertificateToAutomated({
        dnsConfigXref: "dns-1",
        status: "ACTIVE",
      }),
    ).toBe(false);
    expect(
      canConvertManualCertificateToAutomated({
        dnsConfigXref: undefined,
        status: "FAILED",
      }),
    ).toBe(false);
  });
});
