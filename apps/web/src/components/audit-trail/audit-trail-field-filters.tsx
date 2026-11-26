// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { XIcon } from "@phosphor-icons/react";

import { AuditTrailDateFilter } from "@/components/audit-trail/audit-trail-date-filter";
import { TextFilter } from "@/components/audit-trail/audit-trail-filters";
import { Button } from "@/components/ui/button";
import {
  type FilterChipOption,
  FilterSelectChip,
} from "@/components/ui/filter-select-chip";
import { platformVisibility } from "@/lib/audit-trail-filters";
import type { AuditTrailOptionLists } from "@/hooks/audit-trail";
import type {
  AuditTrailFilterField,
  AuditTrailOption,
  AuditTrailSource,
} from "@/lib/audit-trail-source";
import {
  AUDIT_TRAIL_ALL_VISIBILITIES,
  AUDIT_TRAIL_SYSTEM_MEMBER,
  type AuditTrailFilters,
} from "@/types/audit-trail";

/** The chip's "no filter" value (`FilterSelectChip`'s). */
const ALL = "all";
const DEFAULT_DATE_PLACEHOLDER = "Last 90 days";

const toChipOptions = (
  options: readonly AuditTrailOption[] | undefined,
  labelOf: (code: string) => string,
): FilterChipOption[] =>
  (options ?? []).map((option) =>
    typeof option === "string"
      ? { value: option, label: labelOf(option) }
      : option,
  );

/** A value from a link may be one the list does not hold yet. */
const withValue = (
  options: FilterChipOption[],
  value: string,
): FilterChipOption[] =>
  value === ALL || options.some((option) => option.value === value)
    ? options
    : [{ value, label: value }, ...options];

interface AuditTrailFieldFilterBarProps {
  source: Pick<AuditTrailSource, "codeLabel" | "codes" | "datePresets"> & {
    filters: Pick<AuditTrailSource["filters"], "has">;
    copy: Pick<AuditTrailSource["copy"], "datePlaceholder">;
  };
  fields: readonly AuditTrailFilterField[];
  filters: AuditTrailFilters;
  options: AuditTrailOptionLists;
  /** The earliest moment the reader may see, from the server's window. */
  visibleFrom?: Date;
  rangeError?: string;
  onChange: (filters: AuditTrailFilters) => void;
}

/**
 * A source's own filters as inline chips (dashed when unset), in the order
 * the source names them, with the search first.
 */
export function AuditTrailFieldFilterBar({
  source,
  fields,
  filters,
  options,
  visibleFrom,
  rangeError,
  onChange,
}: AuditTrailFieldFilterBarProps) {
  const { codeLabel } = source;
  const set = (patch: Partial<AuditTrailFilters>) =>
    onChange({ ...filters, ...patch });
  const chipValue = (value: string | undefined) => value || ALL;
  const fromChip = (value: string) => (value === ALL ? undefined : value);

  const renderField = (field: AuditTrailFilterField) => {
    switch (field) {
      case "requestId":
        return (
          <TextFilter
            key={field}
            label="Request ID"
            placeholder="Search by request ID"
            value={filters.requestId}
            onCommit={(value) => set({ requestId: value })}
          />
        );
      case "member": {
        const value =
          filters.actorType === AUDIT_TRAIL_SYSTEM_MEMBER
            ? AUDIT_TRAIL_SYSTEM_MEMBER
            : chipValue(filters.userId);
        return (
          <FilterSelectChip
            key={field}
            label="Member"
            value={value}
            options={withValue(
              toChipOptions(options.members, codeLabel),
              value,
            )}
            onValueChange={(next) =>
              set(
                next === AUDIT_TRAIL_SYSTEM_MEMBER
                  ? { actorType: AUDIT_TRAIL_SYSTEM_MEMBER, userId: undefined }
                  : { userId: fromChip(next), actorType: undefined },
              )
            }
          />
        );
      }
      case "category": {
        const value = chipValue(filters.category);
        return (
          <FilterSelectChip
            key={field}
            label="Category"
            value={value}
            options={withValue(
              toChipOptions(options.categories, codeLabel),
              value,
            )}
            onValueChange={(next) => set({ category: fromChip(next) })}
          />
        );
      }
      case "organization": {
        const value = chipValue(filters.organizationId);
        return (
          <FilterSelectChip
            key={field}
            label="Organization"
            value={value}
            options={withValue(
              toChipOptions(options.organizations, codeLabel),
              value,
            )}
            onValueChange={(next) => set({ organizationId: fromChip(next) })}
          />
        );
      }
      case "result":
        return (
          <FilterSelectChip
            key={field}
            label="Result"
            value={chipValue(filters.status)}
            options={toChipOptions(source.codes.results, codeLabel)}
            onValueChange={(next) => set({ status: fromChip(next) })}
          />
        );
      case "actorType":
        return (
          <FilterSelectChip
            key={field}
            label="Actor type"
            value={chipValue(filters.actorType)}
            options={toChipOptions(source.codes.actorTypes, codeLabel)}
            onValueChange={(next) => set({ actorType: fromChip(next) })}
          />
        );
      case "visibility": {
        // Customer rows are the default, so they are the chip's unset value.
        const chosen = platformVisibility(filters.visibility);
        return (
          <FilterSelectChip
            key={field}
            label="Visibility"
            value={chosen === platformVisibility(undefined) ? ALL : chosen}
            options={[
              { value: ALL, label: codeLabel(platformVisibility(undefined)) },
              { value: "INTERNAL", label: codeLabel("INTERNAL") },
              {
                value: AUDIT_TRAIL_ALL_VISIBILITIES,
                label: codeLabel(AUDIT_TRAIL_ALL_VISIBILITIES),
              },
            ]}
            onValueChange={(next) => set({ visibility: fromChip(next) })}
          />
        );
      }
      case "date":
        return (
          <AuditTrailDateFilter
            key={field}
            value={{ range: filters.range, from: filters.from, to: filters.to }}
            presets={source.datePresets ?? []}
            placeholder={
              source.copy.datePlaceholder ?? DEFAULT_DATE_PLACEHOLDER
            }
            earliest={visibleFrom}
            onChange={(date) =>
              set({ range: date.range, from: date.from, to: date.to })
            }
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="space-y-2">
      <div
        role="group"
        aria-label="Filters"
        className="flex flex-wrap items-center gap-2"
      >
        {fields.map(renderField)}
        {source.filters.has(filters) ? (
          <Button variant="ghost" size="sm" onClick={() => onChange({})}>
            <XIcon aria-hidden />
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
