// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { XIcon } from "@phosphor-icons/react";

import {
  CodeSelect,
  TextFilter,
} from "@/components/audit-trail/audit-trail-filters";
import { Button } from "@/components/ui/button";
import { DateRangePicker } from "@/components/ui/date-range-picker";
import type { AuditTrailAccessSource } from "@/lib/audit-trail-source";
import type { AuditTrailAccessFilters as Filters } from "@/types/audit-trail";

interface AuditTrailAccessFilterBarProps {
  source: Pick<
    AuditTrailAccessSource,
    "codeLabel" | "activityLabel" | "results"
  > & {
    filters: Pick<AuditTrailAccessSource["filters"], "has">;
    copy: Pick<
      AuditTrailAccessSource["copy"],
      "target" | "targetPlaceholder" | "datePlaceholder"
    >;
  };
  filters: Filters;
  activities: readonly string[];
  rangeError?: string;
  onChange: (filters: Filters) => void;
}

export function AuditTrailAccessFilterBar({
  source,
  filters,
  activities,
  rangeError,
  onChange,
}: AuditTrailAccessFilterBarProps) {
  const set = (key: keyof Filters, value: string | undefined) =>
    onChange({ ...filters, [key]: value });

  return (
    <div className="space-y-2">
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
        <TextFilter
          label={source.copy.target}
          placeholder={source.copy.targetPlaceholder}
          value={filters.resourceName}
          onCommit={(value) => set("resourceName", value)}
        />
        <TextFilter
          label="User ID"
          placeholder="User ID"
          inputMode="numeric"
          value={filters.userId}
          onCommit={(value) => set("userId", value)}
        />
        <CodeSelect
          label="Activity"
          allLabel="All activity"
          value={filters.activity}
          codes={activities}
          labelOf={source.activityLabel}
          onChange={(value) => set("activity", value)}
        />
        <CodeSelect
          label="Result"
          allLabel="All results"
          value={filters.status}
          codes={source.results}
          labelOf={source.codeLabel}
          onChange={(value) => set("status", value)}
        />
        <DateRangePicker
          value={{ from: filters.from ?? "", to: filters.to ?? "" }}
          onChange={(range) =>
            onChange({
              ...filters,
              from: range.from || undefined,
              to: range.to || undefined,
            })
          }
          placeholder={source.copy.datePlaceholder ?? "Last 90 days"}
          className="h-9 w-full sm:w-64"
        />
        {source.filters.has(filters) ? (
          <Button variant="ghost" size="sm" onClick={() => onChange({})}>
            <XIcon />
            Clear filters
          </Button>
        ) : null}
      </div>
      {rangeError ? (
        <p role="alert" className="text-sm status-danger-text">
          {rangeError}
        </p>
      ) : null}
    </div>
  );
}
