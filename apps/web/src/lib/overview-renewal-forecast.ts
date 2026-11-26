// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { parseDateValue } from "@/lib/utils";

/** The least a forecast needs from a certificate. */
export interface ForecastCertificate {
  domain: string;
  status: string;
  validTo?: string | null;
}

export interface ForecastWeek {
  /** ISO date (UTC midnight) the week starts on. */
  start: string;
  /** Monday-based label for the axis, e.g. "27 Oct". */
  label: string;
  count: number;
  /** Up to three names, for the tooltip. */
  domains: string[];
}

export interface RenewalForecast {
  /** Certificates past their validTo that are not marked expired or revoked. */
  overdue: number;
  within30: number;
  within60: number;
  within90: number;
  /** The next twelve weeks, starting with the current one. */
  weeks: ForecastWeek[];
  /** The week with the most expiries, when any week has one. */
  peak: ForecastWeek | null;
  /** Certificates with a parsable expiry that the forecast is built from. */
  counted: number;
}

export const FORECAST_WEEKS = 12;
const DAY_MS = 24 * 60 * 60 * 1000;
const WEEK_MS = 7 * DAY_MS;

/** Statuses whose expiry is history, not a renewal to plan. */
const SETTLED = new Set(["EXPIRED", "REVOKED", "DELETED", "CANCELLED"]);

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

function startOfUtcDay(ms: number): number {
  return Math.floor(ms / DAY_MS) * DAY_MS;
}

function weekLabel(startMs: number): string {
  const date = new Date(startMs);
  return `${date.getUTCDate()} ${MONTHS[date.getUTCMonth()]}`;
}

/**
 * Groups upcoming expiries into the next {@link FORECAST_WEEKS} weeks so a renewal wave (many
 * certificates issued together, all due the same week) is visible before it arrives. Weeks start on
 * the current UTC day, so the first bucket is "the coming seven days".
 */
export function buildRenewalForecast(
  certificates: ReadonlyArray<ForecastCertificate>,
  now: number = Date.now(),
): RenewalForecast {
  const today = startOfUtcDay(now);
  const weeks: ForecastWeek[] = Array.from(
    { length: FORECAST_WEEKS },
    (_, index) => {
      const start = today + index * WEEK_MS;
      return {
        start: new Date(start).toISOString(),
        label: weekLabel(start),
        count: 0,
        domains: [],
      };
    },
  );
  const forecast: RenewalForecast = {
    overdue: 0,
    within30: 0,
    within60: 0,
    within90: 0,
    weeks,
    peak: null,
    counted: 0,
  };

  for (const certificate of certificates) {
    if (SETTLED.has(certificate.status)) continue;
    const expiry = parseDateValue(certificate.validTo ?? null);
    if (!expiry) continue;
    forecast.counted += 1;
    const remainingMs = expiry.getTime() - now;
    if (remainingMs <= 0) {
      forecast.overdue += 1;
      continue;
    }
    const days = remainingMs / DAY_MS;
    if (days <= 30) forecast.within30 += 1;
    if (days <= 60) forecast.within60 += 1;
    if (days <= 90) forecast.within90 += 1;
    const index = Math.floor((expiry.getTime() - today) / WEEK_MS);
    if (index >= 0 && index < FORECAST_WEEKS) {
      const week = weeks[index];
      week.count += 1;
      if (week.domains.length < 3) week.domains.push(certificate.domain);
    }
  }

  let peak: ForecastWeek | null = null;
  for (const week of weeks) {
    if (week.count > 0 && (peak === null || week.count > peak.count))
      peak = week;
  }
  forecast.peak = peak;
  return forecast;
}
