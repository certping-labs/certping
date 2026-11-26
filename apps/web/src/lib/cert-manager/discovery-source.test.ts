// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getDiscoverySourceDetail } from "./discovery-source";

describe("getDiscoverySourceDetail", () => {
  it("extracts account and region from an ACM ARN", () => {
    expect(
      getDiscoverySourceDetail(
        "arn:aws:acm:us-east-1:123456789012:certificate/abc-123",
      ),
    ).toBe("123456789012 · us-east-1");
  });

  it("extracts the vault name from an Azure Key Vault id", () => {
    expect(
      getDiscoverySourceDetail(
        "https://my-prod-vault.vault.azure.net/certificates/foo/v1",
      ),
    ).toBe("my-prod-vault");
  });

  it("returns null for empty or unrecognized resource ids", () => {
    expect(getDiscoverySourceDetail(null)).toBeNull();
    expect(getDiscoverySourceDetail(undefined)).toBeNull();
    expect(getDiscoverySourceDetail("")).toBeNull();
    expect(getDiscoverySourceDetail("not-a-known-format")).toBeNull();
  });

  it("falls back gracefully when an ARN is missing parts", () => {
    expect(getDiscoverySourceDetail("arn:aws:acm:us-east-1::")).toBe(
      "us-east-1",
    );
  });
});
