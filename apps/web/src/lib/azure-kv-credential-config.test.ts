// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  parseAzureKvCredentialConfig,
  getAzureKvAuthModeLabel,
  getAzureKvAuthModeHelp,
  isAzureKvProvider,
  isAzureKvKvPathRequired,
} from "@/lib/credential-config-schemas/azure-kv";

describe("azure kv credential config", () => {
  it("parses string and object config payloads", () => {
    const payload = {
      authMode: "SERVICE_PRINCIPAL",
      vaultUri: "https://example.vault.azure.net/",
      tenantId: "tenant-id",
    } as const;

    expect(parseAzureKvCredentialConfig(JSON.stringify(payload))).toEqual(
      payload,
    );
    expect(parseAzureKvCredentialConfig(payload)).toEqual(payload);
  });

  it("parses nested config object payloads and rejects invalid payloads", () => {
    expect(
      parseAzureKvCredentialConfig({
        config: {
          authMode: "WORKLOAD_IDENTITY",
          tenantId: "tenant-id",
          vaultUri: "https://example.vault.azure.net/",
        },
      }),
    ).toEqual({
      authMode: "WORKLOAD_IDENTITY",
      tenantId: "tenant-id",
      vaultUri: "https://example.vault.azure.net/",
    });

    expect(parseAzureKvCredentialConfig({ bad: true })).toBeNull();
    expect(parseAzureKvCredentialConfig("{bad-json")).toBeNull();
  });

  it("returns labels/help and provider utilities", () => {
    expect(getAzureKvAuthModeLabel("SERVICE_PRINCIPAL")).toBe(
      "Service principal (client secret)",
    );
    expect(getAzureKvAuthModeHelp("WORKLOAD_IDENTITY")).toContain("runtime");
    expect(isAzureKvProvider("AZURE_KV")).toBe(true);
    expect(isAzureKvProvider("AWS_ACM")).toBe(false);
    expect(isAzureKvKvPathRequired("WORKLOAD_IDENTITY")).toBe(false);
    expect(isAzureKvKvPathRequired("SERVICE_PRINCIPAL")).toBe(true);
  });
});
