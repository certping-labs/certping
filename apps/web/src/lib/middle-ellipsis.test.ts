// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { middleEllipsis } from "@/lib/middle-ellipsis";

describe("middleEllipsis", () => {
  it("keeps the prefix and suffix of a long id", () => {
    expect(
      middleEllipsis("req-http-f740c5eb-6e74-4dd4-a321-b3b48b1d6e69"),
    ).toBe("req-http-f740…6e69");
  });

  it("leaves an id that already fits as it is", () => {
    expect(middleEllipsis("req-405420498018387")).toBe("req-405420498018387");
    expect(middleEllipsis("x".repeat(20))).toBe("x".repeat(20));
    expect(middleEllipsis("x".repeat(21))).toBe(`${"x".repeat(13)}…xxxx`);
    expect(middleEllipsis("")).toBe("");
  });

  it("takes other lengths", () => {
    expect(
      middleEllipsis("abcdefghijklmnop", { max: 6, head: 3, tail: 2 }),
    ).toBe("abc…op");
  });
});
