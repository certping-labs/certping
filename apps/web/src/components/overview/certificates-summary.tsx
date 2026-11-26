// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React from "react";
import {
  WarningIcon,
  ArrowRightIcon,
  CheckCircleIcon,
  ClockIcon,
  PlusIcon,
  ShieldIcon,
  XCircleIcon,
} from "@phosphor-icons/react";

import { MetricCard, MetricStrip } from "@/components/common/metric-card";
import { Button } from "@/components/ui/button";
import type { CertificateSummary } from "@/hooks/overview-signals";

export function CertificatesSummary({
  summary,
  canIssue,
}: {
  summary: CertificateSummary | null;
  canIssue: boolean;
}) {
  return (
    <section
      aria-labelledby="certificates-title"
      className="flex flex-col gap-3 rounded-xl border border-border bg-card px-5 py-4 md:flex-row md:items-center md:justify-between"
    >
      <div className="min-w-0 space-y-1.5">
        <h2
          id="certificates-title"
          className="text-[15px] font-semibold tracking-[-0.015em] text-foreground"
        >
          Certificates
        </h2>
        <MetricStrip aria-label="Certificate summary">
          <MetricCard
            title={summary?.total === 1 ? "certificate" : "certificates"}
            value={summary?.total ?? 0}
            icon={ShieldIcon}
            isLoading={!summary}
          />
          <MetricCard
            title="active"
            value={summary?.active ?? 0}
            icon={CheckCircleIcon}
            tone="success"
            isLoading={!summary}
          />
          <MetricCard
            title="expiring soon"
            value={summary?.expiring ?? 0}
            icon={WarningIcon}
            tone="warning"
            isLoading={!summary}
          />
          <MetricCard
            title="pending"
            value={summary?.pending ?? 0}
            icon={ClockIcon}
            tone="warning"
            isLoading={!summary}
          />
          <MetricCard
            title="failed"
            value={summary?.failed ?? 0}
            icon={XCircleIcon}
            tone="danger"
            isLoading={!summary}
          />
          {summary && summary.expired > 0 ? (
            <MetricCard
              title="expired"
              value={summary.expired}
              icon={XCircleIcon}
              tone="danger"
            />
          ) : null}
        </MetricStrip>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Button asChild variant="ghost" size="sm">
          <Link href="/cert-manager">
            Open certificates
            <ArrowRightIcon aria-hidden />
          </Link>
        </Button>
        {canIssue ? (
          <Button asChild variant="outline" size="sm">
            <Link href="/cert-manager/add">
              <PlusIcon aria-hidden />
              Issue certificate
            </Link>
          </Button>
        ) : null}
      </div>
    </section>
  );
}
