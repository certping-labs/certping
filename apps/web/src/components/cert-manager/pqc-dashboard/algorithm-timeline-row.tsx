// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { cn } from "@/lib/utils";
import type { QuantumStatus } from "@/types/cbom-pqc";
import type { AlgorithmGroup } from "./pqc-dashboard-model";

const STATUS_LINE: Record<QuantumStatus, string> = {
  DEPRECATED_2030: "bg-warning",
  DISALLOWED_2035: "bg-danger",
  PQC_COMPLIANT: "bg-success",
  UNKNOWN: "bg-muted-foreground",
};

const STATUS_CHIP: Record<QuantumStatus, string> = {
  DEPRECATED_2030: "border-warning bg-warning text-black",
  DISALLOWED_2035: "border-danger bg-danger text-destructive-foreground",
  PQC_COMPLIANT: "border-success bg-success text-black",
  UNKNOWN: "border-foreground bg-foreground text-background",
};

export function AlgorithmTimelineRow({ group }: { group: AlgorithmGroup }) {
  return (
    <div className="grid grid-cols-[210px_minmax(0,1fr)] border-b border-border/70 last:border-b-0">
      <div className="min-w-0 px-4 py-3">
        <p
          className="truncate text-sm font-semibold text-foreground"
          title={group.algorithm}
        >
          {group.algorithm}
        </p>
        <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
          {group.keyDetails}
        </p>
      </div>
      <div className="relative min-h-16">
        <YearGrid />
        <StatusTrack group={group} />
      </div>
    </div>
  );
}

function YearGrid() {
  return (
    <div className="absolute inset-0 grid grid-cols-[repeat(13,minmax(56px,1fr))] px-2">
      {Array.from({ length: 13 }).map((_, index) => (
        <span
          key={index}
          className="border-l border-border/50 first:border-l-0"
        />
      ))}
      <span className="absolute top-0 bottom-0 left-1/2 border-l border-primary/45" />
      <span className="absolute top-0 bottom-0 left-[88.462%] border-l border-primary/45" />
    </div>
  );
}

function StatusTrack({ group }: { group: AlgorithmGroup }) {
  const status = group.quantumStatus;
  const solidRange =
    status === "DEPRECATED_2030"
      ? "left-[3.846%] right-1/2"
      : status === "DISALLOWED_2035"
        ? "left-[3.846%] right-[11.538%]"
        : "left-[3.846%] right-[3.846%]";
  const dashedRange =
    status === "DEPRECATED_2030"
      ? "left-1/2 right-[3.846%]"
      : status === "DISALLOWED_2035"
        ? "left-[88.462%] right-[3.846%]"
        : "left-[3.846%] right-[3.846%]";

  return (
    <div className="absolute inset-x-0 top-1/2 -translate-y-1/2">
      <span className="absolute top-0 right-[3.846%] left-[3.846%] h-0.5 bg-[hsl(var(--secondary-300))] dark:bg-[hsl(var(--secondary-500))]" />
      {status !== "UNKNOWN" ? (
        <span
          className={cn(
            "absolute top-0 h-0.5",
            STATUS_LINE[status],
            solidRange,
          )}
        />
      ) : null}
      {status !== "PQC_COMPLIANT" ? (
        <span
          className={cn(
            "absolute top-0 border-t-2 border-dashed",
            status === "UNKNOWN"
              ? "border-muted-foreground"
              : "border-[hsl(var(--secondary-500))] dark:border-[hsl(var(--secondary-600))]",
            dashedRange,
          )}
        />
      ) : null}
      <span
        className={cn(
          "absolute top-0 left-[3.846%] size-2.5 -translate-x-1/2 translate-y-[-4px] rounded-full ring-2 ring-card",
          STATUS_LINE[status],
        )}
      />
      <span
        className={cn(
          "absolute top-0 left-[12%] z-10 min-w-8 -translate-y-1/2 rounded-md border px-2 py-0.5 text-center text-[10px] font-bold tabular-nums",
          STATUS_CHIP[status],
        )}
      >
        {group.count.toLocaleString()}
      </span>
    </div>
  );
}
