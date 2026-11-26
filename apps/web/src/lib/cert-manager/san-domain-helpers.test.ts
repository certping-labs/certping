// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  buildSanCredentialGroups,
  getSanGroupingKey,
  isSanRedundantWithBase,
  normalizeSanDomains,
} from "@/lib/cert-manager/san-domain-helpers";

describe("san-domain-helpers", () => {
  it("groups SANs by root domain key", () => {
    expect(
      buildSanCredentialGroups([
        "api.xyz.com",
        "main.xyz.com",
        "api.abc.com",
        "main.abc.com",
      ]),
    ).toEqual([
      {
        key: "abc.com",
        domains: ["api.abc.com", "main.abc.com"],
      },
      {
        key: "xyz.com",
        domains: ["api.xyz.com", "main.xyz.com"],
      },
    ]);
  });

  it("computes grouping key for wildcard SANs", () => {
    expect(getSanGroupingKey("*.api.xyz.com")).toBe("xyz.com");
    expect(getSanGroupingKey("*.xyz.com")).toBe("xyz.com");
  });

  it("marks redundant SANs when wildcard is enabled on base domain", () => {
    expect(isSanRedundantWithBase("*.xyz.com", "xyz.com", true)).toBe(
      "already covered by primary wildcard",
    );
    expect(isSanRedundantWithBase("api.xyz.com", "xyz.com", true)).toBe(
      "already covered by primary wildcard",
    );
    expect(isSanRedundantWithBase("xyz.com", "xyz.com", true)).toBeNull();
  });

  it("allows wildcard SANs for the primary domain when primary wildcard is disabled", () => {
    expect(
      isSanRedundantWithBase("*.app.example.com", "app.example.com", false),
    ).toBeNull();
    expect(
      isSanRedundantWithBase("app.example.com", "app.example.com", false),
    ).toBe("already covered by the primary domain");
  });

  it("allows deeper wildcard SANs when not covered by base wildcard", () => {
    expect(isSanRedundantWithBase("*.dev.xyz.com", "xyz.com", true)).toBeNull();
    expect(
      isSanRedundantWithBase("*.app.example.com", "example.com", true),
    ).toBeNull();
  });

  it("treats wildcard SAN equal to wildcard CN coverage as redundant for subdomain CN", () => {
    expect(isSanRedundantWithBase("*.b.saamer.com", "b.saamer.com", true)).toBe(
      "already covered by primary wildcard",
    );
    expect(
      isSanRedundantWithBase("*.app.example.com", "app.example.com", true),
    ).toBe("already covered by primary wildcard");
  });

  it("normalizes SAN list and reports conflicts", () => {
    const result = normalizeSanDomains(
      [
        "API.XYZ.COM",
        "*.xyz.com",
        "api.xyz.com",
        "deep.dev.xyz.com",
        "deep.dev.xyz.com",
      ],
      "xyz.com",
      true,
    );

    expect(result.accepted).toEqual(["deep.dev.xyz.com"]);
    expect(result.conflicts).toEqual([
      {
        domain: "api.xyz.com",
        reason: "already covered by primary wildcard",
      },
      {
        domain: "*.xyz.com",
        reason: "already covered by primary wildcard",
      },
    ]);
  });
});
