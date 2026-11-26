// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { format } from "date-fns";
import type { DateRange } from "react-day-picker";
import { CalendarIcon, XIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/lib/utils";

interface DateRangePickerValue {
  from: string;
  to: string;
}

export interface DateRangePickerProps {
  value: DateRangePickerValue;
  onChange: (value: DateRangePickerValue) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}

const toDate = (value: string): Date | undefined => {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }

  const parsed = new Date(trimmed);
  if (Number.isNaN(parsed.getTime())) {
    return undefined;
  }

  return parsed;
};

const toStartOfDayIso = (date: Date): string =>
  new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
    0,
    0,
    0,
    0,
  ).toISOString();

const toEndOfDayIso = (date: Date): string =>
  new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
    23,
    59,
    59,
    999,
  ).toISOString();

const formatRangeLabel = (
  range?: DateRange,
  placeholder = "All dates",
): string => {
  if (!range?.from) {
    return placeholder;
  }

  if (!range.to || range.from.getTime() === range.to.getTime()) {
    return format(range.from, "PPP");
  }

  return `${format(range.from, "PPP")} - ${format(range.to, "PPP")}`;
};

export function DateRangePicker({
  value,
  onChange,
  placeholder = "All dates",
  disabled = false,
  className,
}: DateRangePickerProps) {
  const fromDate = toDate(value.from);
  const toDateValue = toDate(value.to);
  const selectedRange: DateRange | undefined = fromDate
    ? {
        from: fromDate,
        to: toDateValue,
      }
    : undefined;

  const handleSelect = (range?: DateRange) => {
    if (!range?.from) {
      onChange({ from: "", to: "" });
      return;
    }

    const from = toStartOfDayIso(range.from);
    const to = toEndOfDayIso(range.to ?? range.from);
    onChange({ from, to });
  };

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          disabled={disabled}
          className={cn(
            "h-10 w-full justify-start rounded-md border-input bg-card-background px-3 text-left text-foreground hover:bg-card-background hover:text-foreground focus-visible:ring-0 focus-visible:ring-offset-0",
            !selectedRange?.from && "text-muted-foreground",
            className,
          )}
        >
          <CalendarIcon className="h-4 w-4" />
          <span className="truncate">
            {formatRangeLabel(selectedRange, placeholder)}
          </span>
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0" align="start">
        <div className="space-y-3 p-3">
          <Calendar
            mode="range"
            numberOfMonths={2}
            selected={selectedRange}
            onSelect={handleSelect}
            initialFocus
          />
          <div className="flex justify-end border-t border-divider pt-3">
            <Button
              type="button"
              variant="ghost"
              className="h-8 px-3"
              onClick={() => onChange({ from: "", to: "" })}
              disabled={disabled || !value.from}
            >
              <XIcon className="h-4 w-4" />
              Clear
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
