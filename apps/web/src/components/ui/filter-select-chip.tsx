// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

export interface FilterChipOption {
  label: string;
  value: string;
}

export const filterChipClassName =
  "inline-flex h-8 w-auto items-center gap-1.5 whitespace-nowrap rounded-full border px-3 text-xs transition-[background-color,border-color] duration-150 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background [&>svg:last-child]:h-3.5 [&>svg:last-child]:w-3.5";
export const filterChipIdleClassName =
  "border-dashed border-[hsl(var(--control-border-hover))] bg-transparent hover:border-solid hover:bg-secondary";
export const filterChipActiveClassName = "border-border bg-secondary";

export function FilterSelectChip({
  label,
  value,
  options,
  onValueChange,
  disabled,
}: {
  label: string;
  value: string;
  options: readonly FilterChipOption[];
  onValueChange: (value: string) => void;
  disabled?: boolean;
}) {
  const isActive = value !== "all";
  const activeLabel = options.find((option) => option.value === value)?.label;
  return (
    <Select value={value} onValueChange={onValueChange} disabled={disabled}>
      <SelectTrigger
        aria-label={`Filter by ${label}`}
        className={cn(
          filterChipClassName,
          isActive ? filterChipActiveClassName : filterChipIdleClassName,
        )}
      >
        <span className="text-muted-foreground">{label}</span>
        {isActive ? (
          <span className="max-w-40 truncate font-medium text-foreground">
            {activeLabel ?? value}
          </span>
        ) : null}
        <span className="sr-only">
          <SelectValue placeholder="All" />
        </span>
      </SelectTrigger>
      <SelectContent align="start">
        {options.some((option) => option.value === "all") ? null : (
          <SelectItem value="all">All</SelectItem>
        )}
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
