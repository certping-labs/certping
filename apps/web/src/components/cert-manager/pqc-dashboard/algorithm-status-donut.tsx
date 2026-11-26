// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { cn } from "@/lib/utils";
import type { QuantumStatus } from "@/types/cbom-pqc";
import type { StatusBreakdownItem } from "./pqc-dashboard-model";

const CIRCLE_RADIUS = 38;
const CIRCLE_CIRCUMFERENCE = 2 * Math.PI * CIRCLE_RADIUS;
const ZERO_VALUE_MARKER_LENGTH = 3;

const STATUS_STROKE: Record<QuantumStatus, string> = {
  DEPRECATED_2030: "text-warning",
  DISALLOWED_2035: "text-danger",
  PQC_COMPLIANT: "text-success",
  UNKNOWN: "text-muted-foreground",
};

export function AlgorithmStatusDonut({
  breakdown,
  total,
}: {
  breakdown: readonly StatusBreakdownItem[];
  total: number;
}) {
  const segments = buildDonutSegments(breakdown, total);

  return (
    <div
      className="relative size-24 shrink-0"
      aria-label={`Algorithm status for ${total} certificates`}
      role="img"
    >
      <svg className="size-full" viewBox="0 0 96 96" aria-hidden="true">
        <circle
          cx="48"
          cy="48"
          r={CIRCLE_RADIUS}
          fill="none"
          stroke="currentColor"
          strokeWidth="12"
          className="text-muted"
        />
        {segments.map((segment) => (
          <circle
            key={segment.status}
            cx="48"
            cy="48"
            r={CIRCLE_RADIUS}
            fill="none"
            stroke="currentColor"
            strokeWidth="12"
            strokeDasharray={`${segment.length} ${CIRCLE_CIRCUMFERENCE - segment.length}`}
            strokeDashoffset={-segment.offset}
            transform="rotate(-90 48 48)"
            className={cn(STATUS_STROKE[segment.status])}
          />
        ))}
      </svg>
      <span className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-lg font-semibold text-foreground tabular-nums">
          {total.toLocaleString()}
        </span>
        <span className="text-[9px] text-muted-foreground">certs</span>
      </span>
    </div>
  );
}

function buildDonutSegments(
  breakdown: readonly StatusBreakdownItem[],
  total: number,
): Array<{ length: number; offset: number; status: QuantumStatus }> {
  if (total === 0) return [];

  let offset = 0;
  const zeroValueCount = breakdown.filter((item) => item.count === 0).length;
  const availableLength =
    CIRCLE_CIRCUMFERENCE - zeroValueCount * ZERO_VALUE_MARKER_LENGTH;

  return breakdown.map((item) => {
    const length =
      item.count === 0
        ? ZERO_VALUE_MARKER_LENGTH
        : total > 0
          ? (item.count / total) * availableLength
          : 0;
    const segment = { length, offset, status: item.status };
    offset += length;
    return segment;
  });
}
