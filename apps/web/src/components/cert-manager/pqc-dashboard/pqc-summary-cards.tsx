// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  WarningIcon,
  QuestionIcon,
  FileLockIcon,
  ShieldCheckIcon,
  SirenIcon,
} from "@phosphor-icons/react/dist/ssr";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { PqcReadinessSummary } from "@/types/cbom-pqc";

interface PqcSummaryCardsProps {
  isLoading: boolean;
  summary?: PqcReadinessSummary;
}

type MetricTone = "danger" | "neutral" | "primary" | "success" | "warning";

const TONE_CLASSES: Record<MetricTone, string> = {
  danger: "border-danger-border bg-danger-soft text-danger-foreground",
  neutral: "border-border bg-muted text-muted-foreground",
  primary: "border-info-border bg-info-soft text-info-foreground",
  success: "border-success-border bg-success-soft text-success-foreground",
  warning: "border-warning-border bg-warning-soft status-warning-text",
};

export function PqcSummaryCards({ isLoading, summary }: PqcSummaryCardsProps) {
  const total = summary?.totalCertificates ?? 0;
  const metrics = [
    {
      description: "In the current cryptographic inventory",
      icon: FileLockIcon,
      label: "Total certificates",
      tone: "primary" as const,
      value: total,
    },
    {
      description: formatShare(summary?.pqcCompliant ?? 0, total),
      icon: ShieldCheckIcon,
      label: "PQC compliant",
      tone: "success" as const,
      value: summary?.pqcCompliant ?? 0,
    },
    {
      description: "Migration should complete by 2030",
      icon: WarningIcon,
      label: "Deprecated 2030",
      tone: "warning" as const,
      value: summary?.deprecated2030 ?? 0,
    },
    {
      description: "Legacy algorithms disallowed by 2035",
      icon: SirenIcon,
      label: "Disallowed 2035",
      tone: "danger" as const,
      value: summary?.disallowed2035 ?? 0,
    },
    {
      description: "Algorithm metadata needs classification",
      icon: QuestionIcon,
      label: "Unknown status",
      tone: "neutral" as const,
      value: summary?.unknown ?? 0,
    },
  ];

  return (
    <section
      aria-label="PQC readiness summary"
      className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5"
    >
      {metrics.map((metric) => (
        <SummaryCard key={metric.label} isLoading={isLoading} {...metric} />
      ))}
    </section>
  );
}

function SummaryCard({
  description,
  icon: Icon,
  isLoading,
  label,
  tone,
  value,
}: {
  description: string;
  icon: PhosphorIcon;
  isLoading: boolean;
  label: string;
  tone: MetricTone;
  value: number;
}) {
  return (
    <Card className="flex min-h-32 items-start gap-3 p-4">
      <div className={cn("mt-0.5 rounded-lg border p-2", TONE_CLASSES[tone])}>
        <Icon aria-hidden="true" className="size-5" />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-[11px] font-semibold text-muted-foreground">
          {label}
        </p>
        {isLoading ? (
          <Skeleton className="mt-2 h-8 w-20" />
        ) : (
          <p className="mt-1 text-2xl font-semibold tracking-tight text-foreground tabular-nums">
            {value.toLocaleString()}
          </p>
        )}
        <p className="mt-1 text-xs leading-4 text-muted-foreground">
          {description}
        </p>
      </div>
    </Card>
  );
}

function formatShare(count: number, total: number): string {
  const percentage = total > 0 ? Math.round((count / total) * 100) : 0;
  return `${percentage}% of the current inventory`;
}
