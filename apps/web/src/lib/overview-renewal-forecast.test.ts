// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  buildRenewalForecast,
  FORECAST_WEEKS,
} from "./overview-renewal-forecast";

const NOW = Date.UTC(2026, 9, 25, 15, 0, 0); // Sunday 25 Oct 2026, 15:00 UTC
const days = (n: number) =>
  new Date(NOW + n * 24 * 60 * 60 * 1000).toISOString();

describe("buildRenewalForecast", () => {
  it("buckets upcoming expiries into weeks from today and counts the horizons", () => {
    const forecast = buildRenewalForecast(
      [
        { domain: "a.example", status: "ACTIVE", validTo: days(2) },
        { domain: "b.example", status: "ACTIVE", validTo: days(9) },
        { domain: "c.example", status: "ACTIVE", validTo: days(10) },
        { domain: "d.example", status: "ACTIVE", validTo: days(45) },
        { domain: "e.example", status: "ACTIVE", validTo: days(85) },
        { domain: "f.example", status: "ACTIVE", validTo: days(200) },
      ],
      NOW,
    );

    expect(forecast.counted).toBe(6);
    expect(forecast.overdue).toBe(0);
    expect(forecast.within30).toBe(3);
    expect(forecast.within60).toBe(4);
    expect(forecast.within90).toBe(5);
    expect(forecast.weeks).toHaveLength(FORECAST_WEEKS);
    expect(forecast.weeks[0]).toMatchObject({
      label: "25 Oct",
      count: 1,
      domains: ["a.example"],
    });
    expect(forecast.weeks[1]).toMatchObject({
      count: 2,
      domains: ["b.example", "c.example"],
    });
    expect(forecast.weeks[6].count).toBe(1);
    expect(forecast.peak).toBe(forecast.weeks[1]);
  });

  it("counts a certificate past its date as overdue unless its status already settles it", () => {
    const forecast = buildRenewalForecast(
      [
        { domain: "stale.example", status: "ACTIVE", validTo: days(-3) },
        { domain: "gone.example", status: "EXPIRED", validTo: days(-30) },
        { domain: "revoked.example", status: "REVOKED", validTo: days(5) },
        { domain: "unknown.example", status: "ACTIVE", validTo: null },
      ],
      NOW,
    );

    expect(forecast.counted).toBe(1);
    expect(forecast.overdue).toBe(1);
    expect(forecast.weeks.every((week) => week.count === 0)).toBe(true);
    expect(forecast.peak).toBeNull();
  });

  it("keeps at most three names per week but the full count", () => {
    const forecast = buildRenewalForecast(
      ["a", "b", "c", "d", "e"].map((name) => ({
        domain: `${name}.example`,
        status: "ACTIVE",
        validTo: days(3),
      })),
      NOW,
    );
    expect(forecast.weeks[0].count).toBe(5);
    expect(forecast.weeks[0].domains).toEqual([
      "a.example",
      "b.example",
      "c.example",
    ]);
  });
});
