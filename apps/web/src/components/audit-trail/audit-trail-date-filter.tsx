// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { format } from "date-fns";
import type { DateRange } from "react-day-picker";
import {
  CalendarBlankIcon,
  CaretDownIcon,
  CheckIcon,
} from "@phosphor-icons/react";

import { Calendar } from "@/components/ui/calendar";
import {
  filterChipActiveClassName,
  filterChipClassName,
  filterChipIdleClassName,
} from "@/components/ui/filter-select-chip";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import type { AuditTrailDatePreset } from "@/lib/audit-trail-source";
import { cn } from "@/lib/utils";

export interface AuditTrailDateValue {
  range?: string;
  from?: string;
  to?: string;
}

interface AuditTrailDateFilterProps {
  value: AuditTrailDateValue;
  presets: readonly AuditTrailDatePreset[];
  /** What no choice means, e.g. "Last 90 days". */
  placeholder: string;
  /**
   * The earliest moment the reader may see; days before it cannot be chosen,
   * and a range starting on its day starts at it.
   */
  earliest?: Date;
  /** Today, injectable for tests. */
  now?: Date;
  onChange: (value: AuditTrailDateValue) => void;
}

const startOfDay = (date: Date) =>
  new Date(date.getFullYear(), date.getMonth(), date.getDate());

const endOfDay = (date: Date) =>
  new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
    23,
    59,
    59,
    999,
  );

const parse = (value: string | undefined): Date | undefined => {
  if (!value) {
    return undefined;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
};

const DAY_FORMAT = "MMM d, yyyy";

/** What the chip says is chosen; undefined when nothing is. */
export const auditTrailDateLabel = (
  value: AuditTrailDateValue,
  presets: readonly AuditTrailDatePreset[],
): string | undefined => {
  if (value.range) {
    return presets.find((preset) => preset.id === value.range)?.label;
  }
  const from = parse(value.from);
  const to = parse(value.to);
  if (from && to) {
    const start = format(from, DAY_FORMAT);
    const end = format(to, DAY_FORMAT);
    return start === end ? start : `${start} – ${end}`;
  }
  if (from) {
    return `Since ${format(from, DAY_FORMAT)}`;
  }
  if (to) {
    return `Until ${format(to, DAY_FORMAT)}`;
  }
  return undefined;
};

/**
 * The date filter as a chip: presets relative to now, or a custom range of
 * days no earlier than the reader's window.
 */
export function AuditTrailDateFilter({
  value,
  presets,
  placeholder,
  earliest,
  now,
  onChange,
}: AuditTrailDateFilterProps) {
  const [open, setOpen] = useState(false);
  const today = now ?? new Date(Date.now());
  const chosen = auditTrailDateLabel(value, presets);
  const selected: DateRange | undefined = value.range
    ? undefined
    : parse(value.from)
      ? { from: parse(value.from), to: parse(value.to) }
      : undefined;
  const firstDay = earliest ? startOfDay(earliest) : undefined;

  const choosePreset = (preset: AuditTrailDatePreset) => {
    onChange(preset.default ? {} : { range: preset.id });
    setOpen(false);
  };

  const chooseDays = (range: DateRange | undefined) => {
    if (!range?.from) {
      onChange({});
      return;
    }
    const start = startOfDay(range.from);
    // A day chosen on the window's first day starts where the window does.
    const from = earliest && start < earliest ? earliest : start;
    onChange({
      from: from.toISOString(),
      to: endOfDay(range.to ?? range.from).toISOString(),
    });
  };

  const activePreset =
    value.range ??
    (chosen ? undefined : presets.find((preset) => preset.default)?.id);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        aria-label={`Filter by date: ${chosen ?? placeholder}`}
        className={cn(
          filterChipClassName,
          chosen ? filterChipActiveClassName : filterChipIdleClassName,
        )}
      >
        <CalendarBlankIcon
          aria-hidden
          className="h-3.5 w-3.5 text-muted-foreground"
        />
        <span className="text-muted-foreground">Date</span>
        <span
          className={cn(
            "max-w-56 truncate",
            chosen ? "font-medium text-foreground" : "text-muted-foreground",
          )}
        >
          {chosen ?? placeholder}
        </span>
        <CaretDownIcon aria-hidden />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-auto p-0">
        <div className="flex flex-col sm:flex-row">
          <div
            role="group"
            aria-label="Date presets"
            className="flex flex-row flex-wrap gap-1 border-b border-divider p-2 sm:w-44 sm:flex-col sm:flex-nowrap sm:border-r sm:border-b-0"
          >
            {presets.map((preset) => {
              const active = preset.id === activePreset;
              return (
                <button
                  key={preset.id}
                  type="button"
                  aria-pressed={active}
                  onClick={() => choosePreset(preset)}
                  className={cn(
                    "inline-flex h-9 items-center justify-between gap-2 rounded-[10px] px-3 text-left text-sm transition-colors focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden",
                    active
                      ? "bg-primary-soft font-medium text-primary-soft-foreground"
                      : "text-foreground hover:bg-secondary",
                  )}
                >
                  {preset.label}
                  {active ? (
                    <CheckIcon aria-hidden className="h-3.5 w-3.5" />
                  ) : null}
                </button>
              );
            })}
          </div>
          <div className="p-2">
            <p className="px-3 pt-2 text-xs font-medium text-muted-foreground">
              Custom range
            </p>
            <Calendar
              mode="range"
              numberOfMonths={1}
              selected={selected}
              onSelect={chooseDays}
              defaultMonth={selected?.from ?? today}
              fromDate={firstDay}
              toDate={today}
              disabled={[
                ...(firstDay ? [{ before: firstDay }] : []),
                { after: today },
              ]}
            />
            {firstDay ? (
              <p className="max-w-68 px-3 pb-2 text-xs text-muted-foreground">
                The log reaches back to {format(firstDay, DAY_FORMAT)}.
              </p>
            ) : null}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
