// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  connectDnsProviderHref,
  issueCertificateHref,
  safeReturnPath,
} from "@/lib/cert-manager/certificate-journeys";

describe("certificate journeys", () => {
  it.each([
    ["/cert-manager/add?domain=example.com", true],
    ["/", true],
    ["//evil.com", false],
    ["/\\evil.com", false],
    ["/\t/evil.com", false],
    ["https://evil.com", false],
    ["cert-manager", false],
    ["", false],
    [null, false],
  ])("accepts only in-app return paths (%p)", (value, accepted) => {
    expect(safeReturnPath(value)).toBe(accepted ? value : undefined);
  });

  it("links issuing to the add page with the context it has", () => {
    expect(issueCertificateHref()).toBe("/cert-manager/add");
    expect(issueCertificateHref({ domain: "Shop.Example.com." })).toBe(
      "/cert-manager/add?domain=shop.example.com",
    );
    expect(issueCertificateHref({ domain: "*.example.com" })).toBe(
      "/cert-manager/add?domain=example.com&wildcard=1",
    );
    expect(
      issueCertificateHref({ domain: "example.com", wildcard: true }),
    ).toBe("/cert-manager/add?domain=example.com&wildcard=1");
    expect(issueCertificateHref({ from: "cert-1", domain: "a.com" })).toBe(
      "/cert-manager/add?from=cert-1&domain=a.com",
    );
    expect(issueCertificateHref({ domain: "<b>bad</b>" })).toBe(
      "/cert-manager/add",
    );
  });

  it("carries a safe return path to the DNS connection flow", () => {
    expect(connectDnsProviderHref()).toBe(
      "/integrations/connections/add?type=DNS",
    );
    expect(connectDnsProviderHref("/cert-manager/add?domain=a.com")).toBe(
      "/integrations/connections/add?type=DNS&returnTo=%2Fcert-manager%2Fadd%3Fdomain%3Da.com",
    );
    expect(connectDnsProviderHref("//evil.com")).toBe(
      "/integrations/connections/add?type=DNS",
    );
  });
});
