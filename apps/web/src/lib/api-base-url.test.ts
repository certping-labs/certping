// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiBaseUrl, SAME_ORIGIN } from "@/lib/api-base-url";

describe("apiBaseUrl on the Next.js server", () => {
  it("resolves same-origin to the public URL from the runtime environment", () => {
    process.env.NEXT_PUBLIC_API_URL = SAME_ORIGIN;
    process.env.CERTPING_URL = "https://certping.example.com";
    expect(apiBaseUrl()).toBe("https://certping.example.com");
    delete process.env.CERTPING_URL;
    expect(apiBaseUrl()).toBe("http://localhost");
  });
});
