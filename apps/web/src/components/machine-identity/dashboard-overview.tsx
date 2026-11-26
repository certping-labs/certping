// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Link from "next/link";
import {
  CalendarDotIcon,
  CaretRightIcon,
  CpuIcon,
  CertificateIcon,
  DevicesIcon,
} from "@phosphor-icons/react";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import { MetricCard, MetricStrip } from "@/components/common/metric-card";
import {
  CaConnectorList,
  OverviewPanel,
  SourceBreakdownList,
} from "@/components/machine-identity/overview-panels";
import { Skeleton } from "@/components/ui/skeleton";
import { useCaConnectors } from "@/hooks/machine-identity/use-ca-connectors";
import { useCertificateCount } from "@/hooks/machine-identity/use-machine-certificates";
import { useIotSummary } from "@/hooks/machine-identity/use-machine-identity-summary";
import { cn } from "@/lib/utils";

interface MetricDefinition {
  label: string;
  value: number;
  href: string;
  icon: PhosphorIcon;
  /** Non-zero values on these metrics are problems, so they read as warnings. */
  tone: "primary" | "neutral" | "warning" | "danger";
  hint?: string;
  /** The query behind this tile failed - render "—", not a fabricated `0`. */
  hasError?: boolean;
}

/**
 * Machine Identity summary for the main dashboard - the module's only
 * summary surface (there is no separate `/machine-identity` overview page).
 * Every figure comes from `useIotSummary` plus one unfiltered certificate
 * list call reduced client-side (same pattern as the certificates/profiles
 * pages); the By source and CA integration health panels reuse the real
 * `bySource`/`sources` breakdown the summary endpoint already returns
 * instead of leaving most of that payload unused.
 */
export function MachineIdentityDashboardOverview({
  className,
}: {
  className?: string;
}) {
  const summaryQuery = useIotSummary();
  const caConnectorsQuery = useCaConnectors();
  // Server-side counts, shared by query key with the certificate inventory
  // page's own tiles - so the dashboard and the page it links to can never
  // report different numbers, and neither pulls rows it will not render.
  const totalCertificates = useCertificateCount();
  const expiringCertificates = useCertificateCount({ status: "EXPIRING" });
  const expiredCertificates = useCertificateCount({ status: "EXPIRED" });

  const isLoading = summaryQuery.isLoading || totalCertificates.isLoading;

  if (isLoading) {
    return (
      <section className={cn("space-y-3", className)}>
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-24 w-full" />
      </section>
    );
  }

  // A dashboard section stays quiet on failure rather than pushing an error
  // block in front of unrelated widgets.
  if (summaryQuery.error || !summaryQuery.data) {
    return null;
  }

  const summary = summaryQuery.data;

  const metrics: MetricDefinition[] = [
    {
      label: "Devices",
      value: summary.totalDevices,
      href: "/machine-identity/devices",
      icon: DevicesIcon,
      tone: "primary",
      hint: `across ${summary.sources.total} ${summary.sources.total === 1 ? "source" : "sources"}`,
    },
    {
      // Orphaned devices can still hold a live certificate, so the gap between
      // registered and total is an action item, not trivia.
      label: "Orphaned devices",
      value: summary.byStatus.ORPHANED ?? 0,
      href: "/machine-identity/devices?status=ORPHANED",
      icon: CpuIcon,
      tone: (summary.byStatus.ORPHANED ?? 0) > 0 ? "warning" : "neutral",
      hint: `${summary.activeDevices.toLocaleString()} registered`,
    },
    {
      label: "Device certificates",
      value: totalCertificates.data ?? 0,
      href: "/machine-identity/device-certificates",
      icon: CertificateIcon,
      tone: "primary",
      hasError: totalCertificates.isError,
    },
    {
      label: "Expiring or expired",
      value: (expiringCertificates.data ?? 0) + (expiredCertificates.data ?? 0),
      href: "/machine-identity/device-certificates?expiry=EXPIRING",
      icon: CalendarDotIcon,
      hint: `${(expiringCertificates.data ?? 0).toLocaleString()} within 30 days`,
      tone:
        (expiredCertificates.data ?? 0) > 0
          ? "danger"
          : (expiringCertificates.data ?? 0) > 0
            ? "warning"
            : "neutral",
      hasError: expiringCertificates.isError || expiredCertificates.isError,
    },
  ];

  return (
    <section className={cn("space-y-3", className)}>
      <div className="flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-base font-semibold">
          <CpuIcon className="size-4 text-primary" aria-hidden="true" />
          Machine Identity
        </h2>
        <Link
          href="/machine-identity/devices"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          Open devices
          <CaretRightIcon className="size-4" aria-hidden="true" />
        </Link>
      </div>

      <MetricStrip>
        {metrics.map((metric) => (
          <Link key={metric.label} href={metric.href} className="block">
            <MetricCard
              title={metric.label}
              value={metric.hasError ? "—" : metric.value.toLocaleString()}
              description={metric.hasError ? "Unable to load" : metric.hint}
              icon={metric.icon}
              tone={
                metric.hasError
                  ? "neutral"
                  : metric.tone === "danger"
                    ? "danger"
                    : metric.tone === "warning"
                      ? "warning"
                      : metric.tone === "primary"
                        ? "primary"
                        : "neutral"
              }
              density="compact"
              className="h-full transition-colors hover:border-primary/40"
            />
          </Link>
        ))}
      </MetricStrip>

      <div className="grid gap-3 lg:grid-cols-2 lg:items-start">
        <OverviewPanel title="By source">
          <SourceBreakdownList
            bySource={summary.bySource}
            sourceHealth={summary.sources}
          />
        </OverviewPanel>
        <OverviewPanel title="CA integration health">
          <CaConnectorList connectors={caConnectorsQuery.data ?? []} />
        </OverviewPanel>
      </div>
    </section>
  );
}
