// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowsClockwiseIcon,
  ClockCounterClockwiseIcon,
  RocketLaunchIcon,
  ShieldCheckIcon,
  WarningIcon,
} from "@phosphor-icons/react";

import { MetricCard, MetricStrip } from "@/components/common/metric-card";
import { Button } from "@/components/ui/button";
import {
  formatHours,
  getValueSummary,
  type ValueSummary,
} from "@/lib/value-summary";

export const VALUE_SUMMARY_QUERY_KEY = ["value-summary"] as const;

export function useValueSummary(enabled: boolean) {
  return useQuery({
    queryKey: VALUE_SUMMARY_QUERY_KEY,
    queryFn: () => getValueSummary(365),
    enabled,
    staleTime: 5 * 60_000,
    retry: false,
  });
}

/** The panel itself, driven by a summary so it renders the same in tests. */
export function ValueSummaryView({
  summary,
  isLoading,
}: {
  summary: ValueSummary | undefined;
  isLoading: boolean;
}) {
  const nothingYet =
    summary &&
    summary.renewals + summary.automatedDeployments + summary.issuances === 0;
  const a = summary?.assumptions;
  // While loading, keep the card's slot; once loaded, show it only when the
  // server sends a real value for it.
  const showRenewedBeforeExpiry =
    !summary || typeof summary.renewedBeforeExpiry === "number";
  const unmanagedExpiringSoon = summary?.unmanagedExpiringSoon ?? 0;

  return (
    <section
      aria-labelledby="value-title"
      className="space-y-3 rounded-xl border border-border bg-card px-5 py-4"
    >
      <div className="space-y-1">
        <h2
          id="value-title"
          className="text-[15px] font-semibold tracking-[-0.015em] text-foreground"
        >
          What CertPing did for you
        </h2>
        <p className="text-sm text-muted-foreground">
          {nothingYet
            ? "Once CertPing issues, renews and deploys certificates, the work it saves shows up here."
            : "Last 12 months. Work your team did not have to do by hand."}
        </p>
      </div>

      <MetricStrip aria-label="Work CertPing automated">
        <MetricCard
          title="hours saved"
          value={summary ? formatHours(summary.minutesSaved) : 0}
          icon={ClockCounterClockwiseIcon}
          tone="success"
          isLoading={isLoading}
        />
        {showRenewedBeforeExpiry ? (
          <MetricCard
            title="renewed before expiry"
            value={summary?.renewedBeforeExpiry ?? 0}
            icon={ShieldCheckIcon}
            tone="success"
            isLoading={isLoading}
          />
        ) : null}
        <MetricCard
          title="renewals started on schedule"
          value={summary?.scheduledRenewals ?? 0}
          icon={ArrowsClockwiseIcon}
          isLoading={isLoading}
        />
        <MetricCard
          title="deployments done for you"
          value={summary?.automatedDeployments ?? 0}
          icon={RocketLaunchIcon}
          isLoading={isLoading}
        />
      </MetricStrip>

      {summary && summary.unmanagedDiscovered > 0 ? (
        <div className="flex flex-col gap-2 rounded-lg border border-border bg-muted/30 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="flex items-start gap-2 text-sm">
            <WarningIcon
              aria-hidden
              className="mt-0.5 size-4 shrink-0 text-amber-600"
            />
            <span>
              Discovery found {summary.unmanagedDiscovered} certificate
              {summary.unmanagedDiscovered === 1 ? "" : "s"} CertPing does not
              manage yet
              {unmanagedExpiringSoon > 0
                ? `, ${unmanagedExpiringSoon} expiring within 30 days`
                : ""}
              . Each one is a renewal someone has to remember.
            </span>
          </p>
          <Button asChild size="sm" variant="outline">
            <Link href="/cert-manager/discovery">Review</Link>
          </Button>
        </div>
      ) : null}

      {a ? (
        <p className="text-xs text-muted-foreground">
          Hours saved counts {a.minutesPerRenewal} minutes per renewal,{" "}
          {a.minutesPerDeployment} per deployment and {a.minutesPerIssuance} per
          new certificate, the time each takes by hand.
        </p>
      ) : null}
    </section>
  );
}

export function ValueSummaryPanel({ enabled }: { enabled: boolean }) {
  const query = useValueSummary(enabled);
  if (!enabled || query.isError) return null;
  return <ValueSummaryView summary={query.data} isLoading={query.isLoading} />;
}
