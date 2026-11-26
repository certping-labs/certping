// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { describeUserAgent } from "@/lib/user-agent";

describe("describeUserAgent", () => {
  it.each([
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Chrome 129 on macOS",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.2792.79",
      "Edge 129 on Windows",
    ],
    [
      "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
      "Firefox 131 on Linux",
    ],
    [
      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
      "Safari 18 on iOS",
    ],
    [
      "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
      "Chrome 129 on Android",
    ],
    ["curl/8.4.0", "curl 8"],
    ["Mozilla/5.0 (Windows NT 10.0)", "Unknown browser on Windows"],
    ["Mozilla/5.0", "Mozilla/5.0"],
    ["  ", "Unknown"],
  ])("reads %p as %p", (userAgent, expected) => {
    expect(describeUserAgent(userAgent)).toBe(expected);
  });

  it("shortens a long unknown agent", () => {
    expect(describeUserAgent("x".repeat(200))).toHaveLength(121);
  });
});
