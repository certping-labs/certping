// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { PqcReadinessSummary, QuantumStatus } from "@/types/cbom-pqc";
import { AlgorithmStatusDonut } from "./algorithm-status-donut";
import { buildStatusBreakdown } from "./pqc-dashboard-model";

const STATUS_DOT: Record<QuantumStatus, string> = {
  DEPRECATED_2030: "bg-warning",
  DISALLOWED_2035: "bg-danger",
  PQC_COMPLIANT: "bg-success",
  UNKNOWN: "bg-muted-foreground",
};

const COMPACT_LABEL: Record<QuantumStatus, string> = {
  DEPRECATED_2030: "Deprecated",
  DISALLOWED_2035: "Disallowed",
  PQC_COMPLIANT: "PQC ready",
  UNKNOWN: "No data",
};

export function AlgorithmStatusCard({
  summary,
}: {
  summary?: PqcReadinessSummary;
}) {
  const breakdown = buildStatusBreakdown(summary);
  const total = summary?.totalCertificates ?? 0;

  return (
    <Card className="p-4">
      <h2 className="text-sm font-semibold">Algorithm status</h2>
      <p className="mt-0.5 text-[11px] text-muted-foreground">
        By certificate count
      </p>
      <div className="mt-3 flex items-center gap-4">
        <AlgorithmStatusDonut breakdown={breakdown} total={total} />
        <dl className="min-w-0 flex-1 space-y-1.5">
          {breakdown.map((item) => (
            <div
              key={item.status}
              className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2 text-xs"
            >
              <dt className="flex min-w-0 items-center gap-2 text-muted-foreground">
                <span
                  className={cn(
                    "size-2 shrink-0 rounded-full",
                    STATUS_DOT[item.status],
                  )}
                />
                <span className="truncate">{COMPACT_LABEL[item.status]}</span>
              </dt>
              <dd className="shrink-0 font-medium text-foreground tabular-nums">
                {item.count.toLocaleString()}{" "}
                <span className="text-muted-foreground">
                  ({item.percentage}%)
                </span>
              </dd>
            </div>
          ))}
        </dl>
      </div>
      <div className="mt-3 flex items-center justify-between border-t border-border pt-3 text-xs">
        <span className="text-muted-foreground">Total certificates</span>
        <span className="font-semibold text-foreground tabular-nums">
          {total.toLocaleString()}
        </span>
      </div>
    </Card>
  );
}
