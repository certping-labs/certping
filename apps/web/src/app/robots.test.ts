// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import robots from "@/app/robots";

describe("robots", () => {
  it("asks every crawler to stay out of the private console", () => {
    expect(robots()).toEqual({ rules: [{ userAgent: "*", disallow: "/" }] });
  });
});
