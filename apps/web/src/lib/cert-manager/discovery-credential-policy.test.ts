// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { CredentialRecord } from "@/types/ssl";

import {
  getDiscoveryCredentialIneligibilityReason,
  isDiscoveryCredentialEligible,
} from "./discovery-credential-policy";

const baseCredential = (
  overrides: Partial<CredentialRecord> = {},
): CredentialRecord => ({
  id: 1,
  alias: "cred-1",
  credentialXref: "cred-1",
  credentialType: "aws_acm",
  metadata: {},
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  nextRotationAt: "2026-01-01T00:00:00Z",
  rotationInterval: 0,
  version: 1,
  ...overrides,
});

describe("discovery-credential-policy", () => {
  it("allows Azure KV workload identity without secretHandle", () => {
    const credential = baseCredential({
      targetType: "AZURE_KV",
      providerName: "AZURE_KV",
      secretHandle: undefined,
      configJson: JSON.stringify({
        authMode: "WORKLOAD_IDENTITY",
        vaultUri: "https://prod.vault.azure.net/",
        tenantId: "tenant-1",
      }),
    });

    expect(isDiscoveryCredentialEligible(credential)).toBe(true);
    expect(getDiscoveryCredentialIneligibilityReason(credential)).toBeNull();
  });

  it("rejects service-principal credentials without secretHandle", () => {
    const credential = baseCredential({
      targetType: "AZURE_KV",
      providerName: "AZURE_KV",
      configJson: JSON.stringify({ authMode: "SERVICE_PRINCIPAL" }),
    });

    expect(isDiscoveryCredentialEligible(credential)).toBe(false);
    expect(getDiscoveryCredentialIneligibilityReason(credential)).toBe(
      "missing_kv_path",
    );
  });

  it("allows AWS ACM instance profile without secretHandle", () => {
    const credential = baseCredential({
      targetType: "AWS_ACM",
      providerName: "AWS_ACM",
      configJson: JSON.stringify({
        authMode: "INSTANCE_PROFILE",
        region: "us-east-1",
      }),
    });

    expect(isDiscoveryCredentialEligible(credential)).toBe(true);
  });

  it("allows secret-backed AWS ACM credentials with secretHandle", () => {
    const credential = baseCredential({
      targetType: "AWS_ACM",
      providerName: "AWS_ACM",
      secretHandle: "https://vault/secrets/aws",
      configJson: JSON.stringify({
        authMode: "STATIC_KEYS",
        region: "us-east-1",
      }),
    });

    expect(isDiscoveryCredentialEligible(credential)).toBe(true);
  });
});
