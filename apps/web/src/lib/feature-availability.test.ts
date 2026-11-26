// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  resolveFeatureAvailability,
  resolveFeatureSetAvailability,
} from "@/lib/feature-availability";

describe("resolveFeatureAvailability", () => {
  it.each([
    ["pending", {}, "pending"],
    ["error", { A: true }, "error"],
    ["not-applicable", {}, "on"],
    ["ready", { A: true }, "on"],
    ["ready", { A: false }, "off"],
    ["ready", {}, "off"],
  ] as const)(
    "status %s with map %j resolves to %s",
    (status, map, expected) => {
      expect(resolveFeatureAvailability(status, map, "A")).toBe(expected);
    },
  );
});

describe("resolveFeatureSetAvailability", () => {
  it("treats an empty key set as ungated", () => {
    expect(resolveFeatureSetAvailability("pending", {}, [])).toEqual({
      availability: "on",
    });
  });

  it("passes pending and error through untouched", () => {
    expect(resolveFeatureSetAvailability("pending", {}, ["A"])).toEqual({
      availability: "pending",
    });
    expect(resolveFeatureSetAvailability("error", {}, ["A"])).toEqual({
      availability: "error",
    });
  });

  it("opens everything when org flags do not apply", () => {
    expect(
      resolveFeatureSetAvailability("not-applicable", {}, ["A", "B"]),
    ).toEqual({ availability: "on" });
  });

  it("closes an all-of set on the first key that is off and names it", () => {
    expect(
      resolveFeatureSetAvailability("ready", { A: true, B: false }, ["A", "B"]),
    ).toEqual({ availability: "off", blockingKey: "B" });
    expect(
      resolveFeatureSetAvailability("ready", { A: true, B: true }, ["A", "B"]),
    ).toEqual({ availability: "on" });
  });

  it("opens an any-of set when one key is on", () => {
    expect(
      resolveFeatureSetAvailability("ready", { B: true }, ["A", "B"], "any"),
    ).toEqual({ availability: "on" });
    expect(
      resolveFeatureSetAvailability("ready", {}, ["A", "B"], "any"),
    ).toEqual({ availability: "off", blockingKey: "A" });
  });
});
