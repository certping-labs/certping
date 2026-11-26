// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useMemo, useState } from "react";
import { CaretDownIcon } from "@phosphor-icons/react";

import { DetailEmptyState } from "@/components/machine-identity/detail-panel";
import { PanelMasonry } from "@/components/machine-identity/detail-panel";
import { OverviewPanel } from "@/components/machine-identity/overview-panels";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  COMPLIANCE_STATE_LABELS,
  DEVICE_CLASS_LABELS,
  DEVICE_OWNERSHIP_LABELS,
} from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { cn } from "@/lib/utils";
import type {
  IotBooleanBreakdown,
  IotSummary,
} from "@/types/machine-identity-backend";

/** How many rows a breakdown shows before folding the tail into "Other". */
const MAX_BREAKDOWN_ROWS = 5;

interface BreakdownRow {
  key: string;
  label: string;
  value: number;
  /** Applies this slice as a filter on the inventory below. */
  onSelect?: () => void;
  isActive?: boolean;
}

type RowSelection = Pick<BreakdownRow, "onSelect" | "isActive">;

function toRows(
  counts: Record<string, number>,
  labelFor: (key: string) => string,
  select?: (key: string) => RowSelection,
): BreakdownRow[] {
  const entries = Object.entries(counts)
    .filter(([, value]) => value > 0)
    .sort((left, right) => right[1] - left[1]);

  const head = entries.slice(0, MAX_BREAKDOWN_ROWS).map(([key, value]) => ({
    key,
    label: labelFor(key),
    value,
    ...(select?.(key) ?? {}),
  }));

  const tail = entries.slice(MAX_BREAKDOWN_ROWS);
  if (tail.length === 0) return head;

  // Folded rather than truncated: a silently dropped tail makes the visible
  // counts look like they should add up to the fleet total when they do not.
  return [
    ...head,
    {
      key: "__other__",
      label: `${tail.length} more`,
      value: tail.reduce((sum, [, value]) => sum + value, 0),
    },
  ];
}

/**
 * One proportional breakdown of the fleet. Rows are clickable where the
 * backend exposes a matching list filter, so a slice of the chart and the rows
 * in the table below it are always the same query - the tile-equals-filtered-list
 * contract Keyfactor's dashboard collections use.
 *
 * <p>Bars are a share of the dimension's own total, not of its largest slice.
 * Scaling to the largest slice drew a full-width bar next to "macOS 5" out of
 * seven devices, which reads as "all of them".
 */
function Breakdown({
  rows,
  emptyMessage,
}: {
  rows: BreakdownRow[];
  emptyMessage: string;
}) {
  const total = rows.reduce((sum, row) => sum + row.value, 0);
  if (rows.length === 0) {
    return <DetailEmptyState message={emptyMessage} />;
  }

  return (
    <ul className="divide-y divide-border">
      {rows.map((row) => {
        const share = total === 0 ? 0 : (row.value / total) * 100;
        const content = (
          <>
            <span className="flex min-w-0 items-baseline justify-between gap-3">
              <span className="truncate text-sm text-foreground">
                {row.label}
              </span>
              <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
                {row.value.toLocaleString()}
                <span className="ml-1.5 text-muted-foreground/70">
                  {Math.round(share)}%
                </span>
              </span>
            </span>
            <span
              aria-hidden="true"
              className="mt-1.5 block h-1 overflow-hidden rounded-full surface-muted"
            >
              <span
                className={cn(
                  "block h-1 rounded-full",
                  row.isActive ? "bg-primary" : "bg-primary/40",
                )}
                style={{ width: `${share}%` }}
              />
            </span>
          </>
        );

        return (
          <li key={row.key}>
            {row.onSelect ? (
              <button
                type="button"
                onClick={row.onSelect}
                aria-pressed={row.isActive}
                className={cn(
                  "block w-full px-4 py-2.5 text-left transition-colors hover:surface-muted",
                  "focus-visible:ring-2 focus-visible:ring-brand focus-visible:outline-hidden",
                  row.isActive && "surface-muted",
                )}
              >
                {content}
              </button>
            ) : (
              <div className="px-4 py-2.5">{content}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * Coverage of a yes/no/unknown posture control.
 *
 * <p>"Not enabled" is amber, not red: one unencrypted laptop out of seven is
 * something to work through, and painting it the same colour as an outage
 * spends attention the page cannot get back.
 */
function TriStateRow({
  label,
  breakdown,
}: {
  label: string;
  breakdown: IotBooleanBreakdown;
}) {
  const total = breakdown.yes + breakdown.no + breakdown.unknown;
  const share = (count: number) => (total === 0 ? 0 : (count / total) * 100);

  return (
    <div className="px-4 py-2.5">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-sm text-foreground">{label}</span>
        <span className="text-xs text-muted-foreground tabular-nums">
          {breakdown.yes.toLocaleString()} of {total.toLocaleString()}
        </span>
      </div>
      <div
        aria-hidden="true"
        className="mt-1.5 flex h-1 overflow-hidden rounded-full surface-muted"
      >
        <span
          className="h-1 bg-success"
          style={{ width: `${share(breakdown.yes)}%` }}
        />
        <span
          className="h-1 bg-warning"
          style={{ width: `${share(breakdown.no)}%` }}
        />
      </div>
      {breakdown.no > 0 || breakdown.unknown > 0 ? (
        <p className="mt-1 text-xs text-muted-foreground">
          {breakdown.no > 0
            ? `${breakdown.no.toLocaleString()} not enabled`
            : null}
          {breakdown.no > 0 && breakdown.unknown > 0 ? " · " : null}
          {breakdown.unknown > 0
            ? `${breakdown.unknown.toLocaleString()} not reported`
            : null}
        </p>
      ) : null}
    </div>
  );
}

/**
 * One line summarizing what the panels would show, so the section is worth
 * opening (or worth leaving closed) without opening it.
 */
function postureDigest(summary: IotSummary): string {
  const operatingSystems = Object.keys(summary.byOperatingSystem).filter(
    (key) => key !== "UNKNOWN",
  ).length;
  const nonCompliant = summary.byComplianceState.NON_COMPLIANT ?? 0;
  const encrypted = summary.encryption.yes;
  const encryptionTotal =
    summary.encryption.yes + summary.encryption.no + summary.encryption.unknown;

  return [
    `${operatingSystems} ${operatingSystems === 1 ? "operating system" : "operating systems"}`,
    `${nonCompliant.toLocaleString()} non-compliant`,
    encryptionTotal > 0
      ? `${Math.round((encrypted / encryptionTotal) * 100)}% encrypted`
      : "encryption not reported",
  ].join(" · ");
}

interface FleetPosturePanelsProps {
  summary: IotSummary | undefined;
  isLoading: boolean;
  /** Applies an operating-system filter to the inventory below. */
  onSelectOperatingSystem: (operatingSystem: string | undefined) => void;
  activeOperatingSystem: string | undefined;
  onSelectCompliance: (complianceState: string | undefined) => void;
  activeCompliance: string | undefined;
}

/**
 * The parts of `GET /api/v1/iot/summary` the inventory page would otherwise
 * throw away: operating-system, compliance, ownership and device-class
 * breakdowns plus encryption and supervision coverage. The endpoint computes
 * all of it on every call, so leaving it unrendered cost a round trip and told
 * the operator nothing.
 */
export function FleetPosturePanels({
  summary,
  isLoading,
  onSelectOperatingSystem,
  activeOperatingSystem,
  onSelectCompliance,
  activeCompliance,
}: FleetPosturePanelsProps) {
  const operatingSystemRows = useMemo(
    () =>
      toRows(
        summary?.byOperatingSystem ?? {},
        (key) => (key === "UNKNOWN" ? "Not reported" : key),
        (key) =>
          // The list endpoint has no "operating system is null" filter, so the
          // unreported bucket is shown but not offered as a clickable query.
          key === "UNKNOWN"
            ? {}
            : {
                onSelect: () =>
                  onSelectOperatingSystem(
                    activeOperatingSystem === key ? undefined : key,
                  ),
                isActive: activeOperatingSystem === key,
              },
      ),
    [
      summary?.byOperatingSystem,
      onSelectOperatingSystem,
      activeOperatingSystem,
    ],
  );

  const complianceRows = useMemo(
    () =>
      toRows(
        summary?.byComplianceState ?? {},
        (key) => COMPLIANCE_STATE_LABELS[key] ?? humanizeConstant(key),
        (key) => ({
          onSelect: () =>
            onSelectCompliance(activeCompliance === key ? undefined : key),
          isActive: activeCompliance === key,
        }),
      ),
    [summary?.byComplianceState, onSelectCompliance, activeCompliance],
  );

  const ownershipRows = useMemo(
    () =>
      toRows(
        summary?.byOwnership ?? {},
        (key) => DEVICE_OWNERSHIP_LABELS[key] ?? humanizeConstant(key),
      ),
    [summary?.byOwnership],
  );

  const deviceClassRows = useMemo(
    () =>
      toRows(
        summary?.byDeviceClass ?? {},
        (key) => DEVICE_CLASS_LABELS[key] ?? humanizeConstant(key),
      ),
    [summary?.byDeviceClass],
  );

  // Collapsed by default: the inventory table is the reason operators open
  // this page, and four breakdown panels would push it below the fold.
  const [isOpen, setIsOpen] = useState(false);

  if (isLoading) {
    return <Skeleton className="h-8 w-full" />;
  }

  if (!summary) return null;

  return (
    <div className="space-y-3">
      <Button
        variant="outline"
        size="sm"
        className="w-full justify-between"
        aria-expanded={isOpen}
        onClick={() => setIsOpen((open) => !open)}
      >
        <span className="flex min-w-0 items-baseline gap-2">
          <span className="font-medium">Fleet posture</span>
          <span className="truncate text-xs font-normal text-muted-foreground">
            {postureDigest(summary)}
          </span>
        </span>
        <CaretDownIcon
          className={cn("size-4 transition-transform", isOpen && "rotate-180")}
          aria-hidden="true"
        />
      </Button>

      {/*
        Four even panels rather than three lopsided ones: folding ownership,
        device class, encryption and supervision into a single column made one
        panel three times the height of its neighbours and left the other two
        sitting over dead space.
      */}
      {isOpen ? (
        <PanelMasonry columns={3}>
          <OverviewPanel title="Operating systems">
            <Breakdown
              rows={operatingSystemRows}
              emptyMessage="No source has reported an operating system yet."
            />
          </OverviewPanel>

          <OverviewPanel title="Compliance">
            <Breakdown
              rows={complianceRows}
              emptyMessage="No source has reported a compliance state yet."
            />
          </OverviewPanel>

          <OverviewPanel title="Security posture">
            <div className="divide-y divide-border">
              <TriStateRow
                label="Disk encrypted"
                breakdown={summary.encryption}
              />
              <TriStateRow label="Supervised" breakdown={summary.supervision} />
            </div>
          </OverviewPanel>

          <OverviewPanel title="Ownership and class">
            <div className="divide-y divide-border">
              <Breakdown
                rows={ownershipRows}
                emptyMessage="No ownership recorded yet."
              />
              <Breakdown
                rows={deviceClassRows}
                emptyMessage="No device class recorded yet."
              />
            </div>
          </OverviewPanel>
        </PanelMasonry>
      ) : null}
    </div>
  );
}
