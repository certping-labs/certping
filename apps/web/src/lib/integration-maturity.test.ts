// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { CERTIFICATE_AUTHORITY_OPTIONS } from "@/lib/cert-manager/certificate-request-form";
import { DISCOVERY_SOURCE_OPTIONS } from "@/lib/cert-manager/discovery-display";
import { getCredentialReferenceProviderOptions } from "@/lib/credential-providers";
import {
  isBetaIntegration,
  isBetaProviderApiValue,
} from "@/lib/integration-maturity";

// Mirrors docs/integrations.md: only these have an end-to-end lab test.
const TESTED_END_TO_END = {
  DEPLOYMENT: ["KUBERNETES_SECRETS"],
  DNS: ["CERTPING"],
  CA: ["LETS_ENCRYPT"],
  DISCOVERY: ["KUBERNETES_SECRETS"],
} as const;

describe("integration maturity", () => {
  it("marks every deployment target without an end-to-end test as beta", () => {
    for (const option of getCredentialReferenceProviderOptions("DEPLOYMENT")) {
      const tested = (
        TESTED_END_TO_END.DEPLOYMENT as readonly string[]
      ).includes(option.apiValue);
      expect([
        option.apiValue,
        isBetaIntegration("DEPLOYMENT", option.apiValue),
      ]).toEqual([option.apiValue, !tested]);
    }
  });

  it("marks every DNS provider except CertPing DNS as beta", () => {
    for (const option of getCredentialReferenceProviderOptions("DNS")) {
      const tested = (TESTED_END_TO_END.DNS as readonly string[]).includes(
        option.apiValue,
      );
      expect([
        option.apiValue,
        isBetaIntegration("DNS", option.apiValue),
      ]).toEqual([option.apiValue, !tested]);
    }
  });

  it("marks DigiCert and GlobalSign as beta and ACME as tested", () => {
    for (const ca of CERTIFICATE_AUTHORITY_OPTIONS) {
      const tested = (TESTED_END_TO_END.CA as readonly string[]).includes(
        ca.value,
      );
      expect([ca.value, isBetaIntegration("CA", ca.value)]).toEqual([
        ca.value,
        !tested,
      ]);
    }
  });

  it("marks discovery sources other than Kubernetes as beta", () => {
    for (const source of DISCOVERY_SOURCE_OPTIONS) {
      const tested = (
        TESTED_END_TO_END.DISCOVERY as readonly string[]
      ).includes(source.value);
      expect([
        source.value,
        isBetaIntegration("DISCOVERY", source.value),
      ]).toEqual([source.value, !tested]);
    }
  });

  it("treats email as tested and webhook channels as beta", () => {
    expect(isBetaIntegration("NOTIFICATION", "EMAIL")).toBe(false);
    for (const channel of ["SLACK", "TEAMS", "PAGERDUTY", "SERVICENOW_ITSM"]) {
      expect(isBetaIntegration("NOTIFICATION", channel)).toBe(true);
    }
  });

  it("checks a saved credential's provider without knowing its kind", () => {
    expect(isBetaProviderApiValue("kubernetes_secrets")).toBe(false);
    expect(isBetaProviderApiValue("CERTPING")).toBe(false);
    expect(isBetaProviderApiValue("AWS_ACM")).toBe(true);
    expect(isBetaProviderApiValue("CLOUDFLARE")).toBe(true);
    expect(isBetaProviderApiValue("")).toBe(false);
    expect(isBetaProviderApiValue(undefined)).toBe(false);
  });
});
