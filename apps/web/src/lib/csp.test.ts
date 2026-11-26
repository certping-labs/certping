// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiOrigin, buildContentSecurityPolicy, generateNonce } from "./csp";

describe("content security policy", () => {
  it("builds the strict production policy with the nonce and no unsafe script sources", () => {
    expect(buildContentSecurityPolicy({ nonce: "abc" })).toBe(
      "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; " +
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; " +
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; " +
        "object-src 'none'",
    );
  });

  it("adds an absolute API origin to connect-src", () => {
    const policy = buildContentSecurityPolicy({
      nonce: "n",
      apiUrl: "https://api.example.com/base/",
    });
    expect(policy).toContain("connect-src 'self' https://api.example.com;");
  });

  it("ignores relative and same-origin API values", () => {
    expect(apiOrigin("/api-proxy")).toBeNull();
    expect(apiOrigin("same-origin")).toBeNull();
    expect(apiOrigin(undefined)).toBeNull();
    expect(apiOrigin("https://")).toBeNull();
  });

  it("relaxes only in development", () => {
    const policy = buildContentSecurityPolicy({ nonce: "n", isDev: true });
    expect(policy).toContain("'unsafe-eval'");
    expect(policy).toContain("connect-src 'self' ws: wss:");
    expect(policy).not.toMatch(/script-src[^;]*'unsafe-inline'/);
  });

  it("generates a fresh 128-bit base64 nonce each call", () => {
    const first = generateNonce();
    expect(first).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(generateNonce()).not.toBe(first);
  });
});
