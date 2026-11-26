// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { InfoIcon } from "@phosphor-icons/react/dist/ssr";

import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { QuantumStatus } from "@/types/cbom-pqc";
import { AlgorithmTimelineAxis } from "./algorithm-timeline-axis";
import { AlgorithmTimelineRow } from "./algorithm-timeline-row";
import type { AlgorithmGroup } from "./pqc-dashboard-model";
import { PQC_STATUS_COLOR, PQC_STATUS_COPY } from "./pqc-status";

interface AlgorithmTimelineProps {
  groups: readonly AlgorithmGroup[];
  isLoading: boolean;
}

export function AlgorithmTimeline({
  groups,
  isLoading,
}: AlgorithmTimelineProps) {
  return (
    <Card className="min-w-0 overflow-hidden">
      <header className="border-b border-border px-4 py-4 sm:px-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-[15px] font-semibold">
                Certificate distribution timeline
              </h2>
              <InfoIcon
                aria-hidden="true"
                className="size-3.5 text-muted-foreground"
              />
            </div>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Public-key algorithms mapped to NIST transition deadlines.
            </p>
          </div>
          <TimelineLegend />
        </div>
      </header>

      <div className="overflow-x-auto">
        <div className="min-w-[1050px]">
          <AlgorithmTimelineAxis />
          {isLoading ? (
            <div
              className="h-56 animate-pulse bg-muted/30"
              aria-label="Loading algorithm timeline"
            />
          ) : groups.length > 0 ? (
            groups.map((group) => (
              <AlgorithmTimelineRow key={group.algorithm} group={group} />
            ))
          ) : (
            <div className="px-5 py-16 text-center">
              <p className="text-sm font-medium text-foreground">
                No algorithm inventory yet
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                Certificate algorithms will appear after the next inventory
                scan.
              </p>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

function TimelineLegend() {
  return (
    <div
      aria-label="Timeline legend"
      className="flex flex-wrap gap-x-4 gap-y-2 text-xs text-muted-foreground"
    >
      {Object.entries(PQC_STATUS_COPY).map(([status, copy]) => (
        <span key={status} className="inline-flex items-center gap-1.5">
          <span
            className={cn(
              "size-2 rounded-full",
              PQC_STATUS_COLOR[status as QuantumStatus],
            )}
          />
          {copy.label}
        </span>
      ))}
    </div>
  );
}
