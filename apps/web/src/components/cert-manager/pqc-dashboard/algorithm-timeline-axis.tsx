// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { cn } from "@/lib/utils";

const TIMELINE_YEARS = [
  "2024",
  "2025",
  "2026",
  "2027",
  "2028",
  "2029",
  "2030",
  "2031",
  "2032",
  "2033",
  "2034",
  "2035",
  "2036+",
] as const;

export function AlgorithmTimelineAxis() {
  return (
    <div className="grid grid-cols-[210px_minmax(0,1fr)] border-b border-border bg-muted/15">
      <div className="flex items-end px-4 pb-3 text-xs font-medium text-muted-foreground">
        Algorithm
      </div>
      <div>
        <div className="relative h-[74px]">
          <DeadlineCallout
            className="left-1/2 -translate-x-1/2"
            year="2030"
            label="Deprecate vulnerable algorithms"
          />
          <DeadlineCallout
            className="left-[88.462%] -translate-x-1/2"
            year="2035"
            label="Disallow legacy algorithms"
          />
        </div>
        <div className="relative grid grid-cols-[repeat(13,minmax(56px,1fr))] px-2 pb-3 text-center text-[11px] font-medium text-muted-foreground tabular-nums">
          {TIMELINE_YEARS.map((year) => (
            <span key={year} className="flex justify-center">
              {year === "2030" || year === "2035" ? (
                <span
                  aria-label={`${year} deadline year`}
                  className="-my-1 rounded-full border border-primary/45 bg-primary/10 px-2 py-0.5 font-semibold text-primary shadow-[0_0_0_3px_hsl(var(--primary)/0.06)]"
                >
                  {year}
                </span>
              ) : (
                year
              )}
            </span>
          ))}
          <span className="absolute top-0 bottom-0 left-1/2 border-l border-primary/50" />
          <span className="absolute top-0 bottom-0 left-[88.462%] border-l border-primary/50" />
        </div>
      </div>
    </div>
  );
}

function DeadlineCallout({
  className,
  label,
  year,
}: {
  className: string;
  label: string;
  year: string;
}) {
  return (
    <div
      className={cn(
        "absolute top-3 w-40 rounded-md border border-primary/40 bg-card px-2 py-1.5 text-center",
        className,
      )}
    >
      <p className="text-[10px] font-semibold text-primary">
        NIST {year} deadline
      </p>
      <p className="mt-0.5 text-[10px] leading-3 text-muted-foreground">
        {label}
      </p>
      <span className="absolute -bottom-1 left-1/2 size-2 -translate-x-1/2 rotate-45 border-r border-b border-primary/40 bg-card" />
    </div>
  );
}
