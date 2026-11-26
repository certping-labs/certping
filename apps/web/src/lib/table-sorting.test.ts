// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { compareDateValues } from "@/lib/table-sorting";

describe("table-sorting", () => {
  describe("compareDateValues", () => {
    it("returns 0 when both values are invalid or empty", () => {
      expect(compareDateValues("", "   ")).toBe(0);
      expect(compareDateValues(undefined, null)).toBe(0);
    });

    it("treats invalid left value as smaller", () => {
      expect(compareDateValues("not-a-date", "2026-01-01T00:00:00.000Z")).toBe(
        -1,
      );
    });

    it("treats invalid right value as larger", () => {
      expect(compareDateValues("2026-01-01T00:00:00.000Z", "invalid")).toBe(1);
    });

    it("compares numeric timestamps directly", () => {
      expect(compareDateValues(1000, 2000)).toBeLessThan(0);
      expect(compareDateValues(2000, 1000)).toBeGreaterThan(0);
      expect(compareDateValues(2000, 2000)).toBe(0);
    });

    it("compares parseable date strings by timestamp", () => {
      expect(
        compareDateValues(
          "2026-01-01T00:00:00.000Z",
          "2026-01-02T00:00:00.000Z",
        ),
      ).toBeLessThan(0);
    });

    it("treats non-finite numbers as invalid", () => {
      expect(compareDateValues(Number.NaN, 2000)).toBe(-1);
      expect(compareDateValues(Number.POSITIVE_INFINITY, 2000)).toBe(-1);
    });
  });
});
