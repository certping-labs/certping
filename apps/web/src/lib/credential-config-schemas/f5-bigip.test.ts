// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  f5BigipCredentialConfigSchema,
  normalizeF5BigipHost,
  parseF5BigipCredentialConfig,
} from "@/lib/credential-config-schemas/f5-bigip";

describe("f5-bigip credential config", () => {
  describe("normalizeF5BigipHost", () => {
    it("keeps plain hostnames as-is", () => {
      expect(normalizeF5BigipHost("bigip.example.com")).toBe(
        "bigip.example.com",
      );
    });

    it("extracts hostname from a pasted URL", () => {
      expect(normalizeF5BigipHost("https://bigip.example.com/mgmt/tm")).toBe(
        "bigip.example.com",
      );
    });

    it("strips scheme/path/trailing slashes defensively", () => {
      expect(normalizeF5BigipHost("http://10.0.0.1///foo/bar")).toBe(
        "10.0.0.1",
      );
    });
  });

  describe("schema", () => {
    it("defaults clientSslProfiles to a safe bootstrap profile", () => {
      const parsed = f5BigipCredentialConfigSchema.parse({
        bigipHost: "bigip.example.com",
        partition: "Common",
      });
      expect(parsed.clientSslProfiles).toEqual(["clientssl-api"]);
    });
  });

  describe("parseF5BigipCredentialConfig", () => {
    it("returns null for empty input", () => {
      expect(parseF5BigipCredentialConfig(undefined)).toBeNull();
    });

    it("parses both raw objects and nested {config} objects", () => {
      const raw = {
        bigipHost: "https://bigip.example.com/",
        partition: "Common",
        clientSslProfiles: ["clientssl-api"],
      };
      expect(parseF5BigipCredentialConfig(raw)).toEqual({
        bigipHost: "bigip.example.com",
        partition: "Common",
        clientSslProfiles: ["clientssl-api"],
      });

      expect(parseF5BigipCredentialConfig({ config: raw })).toEqual({
        bigipHost: "bigip.example.com",
        partition: "Common",
        clientSslProfiles: ["clientssl-api"],
      });
    });

    it("returns null for invalid JSON strings", () => {
      expect(parseF5BigipCredentialConfig("{nope")).toBeNull();
    });
  });
});
