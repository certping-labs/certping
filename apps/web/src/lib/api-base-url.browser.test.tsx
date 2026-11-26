// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiBaseUrl, SAME_ORIGIN } from "@/lib/api-base-url";

describe("apiBaseUrl", () => {
  const original = process.env.NEXT_PUBLIC_API_URL;
  const originalPublic = process.env.CERTPING_URL;

  afterEach(() => {
    process.env.NEXT_PUBLIC_API_URL = original;
    process.env.CERTPING_URL = originalPublic;
  });

  it("uses the configured URL", () => {
    process.env.NEXT_PUBLIC_API_URL = "https://api.example.com";
    expect(apiBaseUrl()).toBe("https://api.example.com");
  });

  it("falls back when nothing is configured", () => {
    delete process.env.NEXT_PUBLIC_API_URL;
    expect(apiBaseUrl()).toBe("");
    expect(apiBaseUrl("https://api.example.com")).toBe(
      "https://api.example.com",
    );
  });

  it("resolves same-origin to the page's origin in the browser", () => {
    process.env.NEXT_PUBLIC_API_URL = SAME_ORIGIN;
    expect(apiBaseUrl()).toBe(window.location.origin);
  });
});
