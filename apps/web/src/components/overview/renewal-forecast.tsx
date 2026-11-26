// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React from "react";
import { ArrowRightIcon, CalendarBlankIcon } from "@phosphor-icons/react";

import { MetricCard, MetricStrip } from "@/components/common/metric-card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { RenewalForecast } from "@/lib/overview-renewal-forecast";

function barTone(count: number, peak: number): string {
  if (count === 0) return "bg-muted";
  if (peak > 0 && count === peak) return "bg-warning-foreground";
  return "bg-primary/70";
}

/**
 * The next twelve weeks of expiries as a small bar chart, with 30/60/90-day counts: the renewal-wave
 * view that replaces the expiry emails certificate authorities no longer send.
 */
export function RenewalForecastPanel({
  forecast,
  renewalsHref = "/cert-manager/rotation",
}: {
  forecast: RenewalForecast | null;
  renewalsHref?: string;
}) {
  const peak = forecast?.peak?.count ?? 0;
  const maxCount = Math.max(peak, 1);

  return (
    <section
      aria-labelledby="renewal-forecast-title"
      className="space-y-4 rounded-xl border border-border bg-card px-5 py-4"
    >
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0 space-y-1.5">
          <h2
            id="renewal-forecast-title"
            className="text-[15px] font-semibold tracking-[-0.015em] text-foreground"
          >
            Renewal forecast
          </h2>
          <MetricStrip aria-label="Expiries by horizon">
            <MetricCard
              title="overdue"
              value={forecast?.overdue ?? 0}
              tone="danger"
              isLoading={!forecast}
            />
            <MetricCard
              title="in 30 days"
              value={forecast?.within30 ?? 0}
              tone="warning"
              isLoading={!forecast}
            />
            <MetricCard
              title="in 60 days"
              value={forecast?.within60 ?? 0}
              isLoading={!forecast}
            />
            <MetricCard
              title="in 90 days"
              value={forecast?.within90 ?? 0}
              isLoading={!forecast}
            />
          </MetricStrip>
        </div>
        <Button asChild size="sm" variant="outline" className="shrink-0">
          <Link href={renewalsHref}>
            Plan renewals
            <ArrowRightIcon aria-hidden />
          </Link>
        </Button>
      </div>

      {!forecast ? (
        <Skeleton className="h-24 w-full" />
      ) : forecast.counted === 0 ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <CalendarBlankIcon aria-hidden className="h-4 w-4" />
          No certificates with an expiry date yet. The forecast fills in as
          certificates are discovered or issued.
        </p>
      ) : (
        <div className="space-y-2">
          <ol
            aria-label="Expiries per week for the next twelve weeks"
            className="grid grid-cols-12 items-end gap-1.5"
            data-testid="renewal-forecast-weeks"
          >
            {forecast.weeks.map((week) => {
              const height =
                week.count === 0
                  ? 4
                  : Math.max(8, Math.round((week.count / maxCount) * 64));
              const names = week.domains.join(", ");
              const title =
                week.count === 0
                  ? `Week of ${week.label}: no expiries`
                  : `Week of ${week.label}: ${week.count} ${week.count === 1 ? "expiry" : "expiries"}` +
                    (names
                      ? ` (${names}${week.count > week.domains.length ? ", ..." : ""})`
                      : "");
              return (
                <li
                  key={week.start}
                  className="flex flex-col items-center gap-1"
                  title={title}
                  aria-label={title}
                >
                  <span className="text-[11px] text-muted-foreground tabular-nums">
                    {week.count > 0 ? week.count : ""}
                  </span>
                  <span
                    aria-hidden
                    className={cn(
                      "w-full rounded-sm transition-[height]",
                      barTone(week.count, peak),
                    )}
                    style={{ height }}
                  />
                  <span className="text-[10px] text-muted-foreground">
                    {week.label}
                  </span>
                </li>
              );
            })}
          </ol>
          {forecast.peak ? (
            <p className="text-xs text-muted-foreground">
              {`Busiest week starts ${forecast.peak.label} with ${forecast.peak.count} ${
                forecast.peak.count === 1 ? "expiry" : "expiries"
              }. Renew early to spread the wave.`}
            </p>
          ) : (
            <p className="text-xs text-muted-foreground">
              Nothing expires in the next twelve weeks.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
