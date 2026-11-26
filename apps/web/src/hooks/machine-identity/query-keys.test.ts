// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { machineIdentityKeys } from "@/hooks/machine-identity/query-keys";

describe("machineIdentityKeys", () => {
  it("scopes every key to an organization", () => {
    // Switching org context must not serve another tenant's cached rows.
    expect(machineIdentityKeys.deviceList("1")).not.toEqual(
      machineIdentityKeys.deviceList("2"),
    );
    expect(machineIdentityKeys.summary("1")).not.toEqual(
      machineIdentityKeys.summary("2"),
    );
  });

  it("normalizes a blank organization to the same scope as none", () => {
    expect(machineIdentityKeys.devices("   ")).toEqual(
      machineIdentityKeys.devices(undefined),
    );
    expect(machineIdentityKeys.devices(null)).toEqual(
      machineIdentityKeys.devices(undefined),
    );
  });

  it("collapses equivalent list requests onto one cache entry", () => {
    // `{}` and the explicit defaults are the same page; two entries would mean
    // two fetches for one screen.
    expect(machineIdentityKeys.deviceList("1", {})).toEqual(
      machineIdentityKeys.deviceList("1", { page: 0, size: 25 }),
    );
    expect(machineIdentityKeys.certificateList("1", {})).toEqual(
      machineIdentityKeys.certificateList("1", {
        page: 0,
        size: 25,
        sort: "validTo",
        direction: "asc",
      }),
    );
  });

  it("separates requests that differ by a filter", () => {
    expect(
      machineIdentityKeys.deviceList("1", { status: "ORPHANED" }),
    ).not.toEqual(
      machineIdentityKeys.deviceList("1", { status: "REGISTERED" }),
    );
    expect(
      machineIdentityKeys.certificateList("1", { status: "EXPIRED" }),
    ).not.toEqual(machineIdentityKeys.certificateList("1", {}));
  });

  it("nests detail and child keys under their resource prefix so one invalidation clears them", () => {
    const devices = machineIdentityKeys.devices("1");
    for (const key of [
      machineIdentityKeys.deviceList("1"),
      machineIdentityKeys.device("1", "dev_1"),
      machineIdentityKeys.deviceEventList("1", "dev_1"),
      machineIdentityKeys.deviceCertificateList("1", "dev_1"),
    ]) {
      expect(key.slice(0, devices.length)).toEqual([...devices]);
    }
  });

  it("keeps an absent xref addressable instead of producing a sparse key", () => {
    expect(machineIdentityKeys.device("1", undefined).at(-1)).toBeNull();
    expect(machineIdentityKeys.certificate("1", undefined).at(-1)).toBeNull();
    expect(machineIdentityKeys.profile("1", undefined).at(-1)).toBeNull();
  });
});
