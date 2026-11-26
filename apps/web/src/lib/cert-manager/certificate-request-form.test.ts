// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  caAcceptsRequestedValidity,
  caNeedsCustomerKey,
  certificateRequestPrefill,
  certificateRequestSchema,
} from "@/lib/cert-manager/certificate-request-form";
import type { SSLCertificateDetails } from "@/types/ssl";

const base = {
  domain: "shop.example.com",
  status: "FAILED",
} as SSLCertificateDetails;

describe("certificateRequestPrefill", () => {
  it("carries every reusable field of an automated certificate", () => {
    expect(
      certificateRequestPrefill({
        ...base,
        wildcard: true,
        san: true,
        sanDomains: ["API.other.com", "shop.example.com", "bad domain"],
        caProvider: "digicert",
        dnsConfigXref: { "shop.example.com": "dns-1", "other.com": "dns-2" },
        deploymentCredentialXrefs: ["deploy-1"],
      }),
    ).toEqual({
      domain: "shop.example.com",
      wildcard: true,
      san: true,
      sanDomains: ["api.other.com", "shop.example.com"],
      sanCredentialMap: { "other.com": "dns-2" },
      caProvider: "DIGICERT",
      mode: "automated",
      dnsCredentialXref: "dns-1",
      deploymentTargets: ["deploy-1"],
    });
  });

  it("keeps a manual certificate manual and ignores unknown authorities", () => {
    expect(
      certificateRequestPrefill({
        ...base,
        domain: "*.Example.com",
        caProvider: "SOMETHING_ELSE",
      }),
    ).toEqual({
      domain: "example.com",
      wildcard: true,
      san: false,
      sanDomains: [],
      sanCredentialMap: {},
      deploymentTargets: [],
    });
  });

  it("uses the root domain's credential and keeps the apex name on a wildcard certificate", () => {
    expect(
      certificateRequestPrefill({
        ...base,
        domain: "*.example.com",
        wildcard: true,
        san: true,
        sanDomains: ["*.example.com", "example.com", "www.partner.io"],
        dnsConfigXref: {
          "partner.io": "dns-partner",
          "example.com": "dns-root",
        },
      }),
    ).toEqual({
      domain: "example.com",
      wildcard: true,
      san: true,
      sanDomains: ["example.com", "www.partner.io"],
      sanCredentialMap: { "partner.io": "dns-partner" },
      deploymentTargets: [],
      mode: "automated",
      dnsCredentialXref: "dns-root",
    });
  });

  it("drops the primary name from the SANs of a single-name certificate", () => {
    expect(
      certificateRequestPrefill({
        ...base,
        domain: "example.com",
        san: true,
        sanDomains: ["example.com", "www.example.com"],
        dnsConfigXref: { "example.com": "dns-root" },
      }),
    ).toMatchObject({
      domain: "example.com",
      wildcard: false,
      san: true,
      sanDomains: ["www.example.com"],
      sanCredentialMap: {},
      dnsCredentialXref: "dns-root",
    });
  });
});

describe("caAcceptsRequestedValidity", () => {
  it("lets a request choose the lifetime only where the CA honours it", () => {
    expect(caAcceptsRequestedValidity("DIGICERT")).toBe(true);
    expect(caAcceptsRequestedValidity("GLOBALSIGN")).toBe(true);
    expect(caAcceptsRequestedValidity("LETS_ENCRYPT")).toBe(false);
  });
});

describe("the DigiCert API key", () => {
  const request = {
    mode: "automated" as const,
    domain: "shop.example.com",
    dnsCredentialXref: "dns-1",
  };

  it("is needed only by DigiCert", () => {
    expect(caNeedsCustomerKey("DIGICERT")).toBe(true);
    for (const ca of ["LETS_ENCRYPT", "GLOBALSIGN"]) {
      expect(caNeedsCustomerKey(ca)).toBe(false);
    }
  });

  it("is required for an automated DigiCert request", () => {
    const result = certificateRequestSchema.safeParse({
      ...request,
      caProvider: "DIGICERT",
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({
        path: ["caCredentialXref"],
        message: "Add or choose your DigiCert API key",
      }),
    );
    expect(
      certificateRequestSchema.safeParse({
        ...request,
        caProvider: "DIGICERT",
        caCredentialXref: "ca-1",
      }).success,
    ).toBe(true);
  });

  it("is not asked for by other CAs or manual requests", () => {
    expect(
      certificateRequestSchema.safeParse({
        ...request,
        caProvider: "LETS_ENCRYPT",
      }).success,
    ).toBe(true);
    expect(
      certificateRequestSchema.safeParse({
        mode: "manual",
        domain: "shop.example.com",
        caProvider: "DIGICERT",
      }).success,
    ).toBe(true);
  });
});
