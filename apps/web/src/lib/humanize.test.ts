// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { humanizeEnum } from "@/lib/humanize";

describe("humanizeEnum", () => {
  it.each([
    ["RESOLVED", "Resolved"],
    ["DNS_VALIDATION_PENDING", "DNS validation pending"],
    ["publish failed", "Publish failed"],
    ["", ""],
    [null, ""],
  ])("turns %p into %p", (input, output) => {
    expect(humanizeEnum(input)).toBe(output);
  });
});
