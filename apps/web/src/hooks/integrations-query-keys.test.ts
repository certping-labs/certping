// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { integrationQueryKeys } from "@/hooks/integrations";

describe("integrationQueryKeys", () => {
  it("isolates lists and details by normalized organization scope", () => {
    expect(integrationQueryKeys.list(" organization-42 ")).toEqual([
      "integrations",
      "list",
      "organization-42",
    ]);
    expect(integrationQueryKeys.detail("organization-7", 9)).toEqual([
      "integrations",
      "detail",
      "organization-7",
      9,
    ]);
    expect(integrationQueryKeys.list(undefined)).toEqual([
      "integrations",
      "list",
      null,
    ]);
  });
});
