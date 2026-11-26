// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { isUnmanagedDiscoveredCert } from "@/lib/cert-manager/discovery-display";

describe("isUnmanagedDiscoveredCert", () => {
  it("counts managed = false that is not MISSING, as the server does", () => {
    expect(
      isUnmanagedDiscoveredCert({ managed: false, inventoryStatus: "PRESENT" }),
    ).toBe(true);
    expect(
      isUnmanagedDiscoveredCert({ managed: false, inventoryStatus: "UNKNOWN" }),
    ).toBe(true);
    expect(isUnmanagedDiscoveredCert({ managed: false })).toBe(true);
  });

  it("does not count missing, managed or undecided certificates", () => {
    expect(
      isUnmanagedDiscoveredCert({ managed: false, inventoryStatus: "MISSING" }),
    ).toBe(false);
    expect(
      isUnmanagedDiscoveredCert({ managed: true, inventoryStatus: "PRESENT" }),
    ).toBe(false);
    expect(
      isUnmanagedDiscoveredCert({ managed: null, inventoryStatus: "PRESENT" }),
    ).toBe(false);
  });
});
