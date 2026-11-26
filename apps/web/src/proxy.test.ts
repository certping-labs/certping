// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { NextRequest } from "next/server";

import { config, proxy } from "./proxy";

describe("proxy", () => {
  it("sends a nonce policy on the response and hands the nonce to rendering", () => {
    const response = proxy(new NextRequest("http://localhost/login"));
    const policy = response.headers.get("Content-Security-Policy") ?? "";
    const nonce = /'nonce-([^']+)'/.exec(policy)?.[1];

    expect(nonce).toBeTruthy();
    expect(policy).toContain("frame-ancestors 'none'");
    expect(response.headers.get("x-middleware-request-x-nonce")).toBe(nonce);
  });

  it("uses a new nonce per request", () => {
    const a = proxy(new NextRequest("http://localhost/")).headers.get(
      "Content-Security-Policy",
    );
    const b = proxy(new NextRequest("http://localhost/")).headers.get(
      "Content-Security-Policy",
    );
    expect(a).not.toBe(b);
  });

  it("skips route handlers and build assets", () => {
    const pattern = new RegExp(`^${config.matcher[0].source}$`);
    expect(pattern.test("/login")).toBe(true);
    expect(pattern.test("/api/health")).toBe(false);
    expect(pattern.test("/_next/static/chunks/a.js")).toBe(false);
  });
});
