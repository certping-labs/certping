// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { MagnifyingGlassIcon, XIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { FilterSelectChip } from "@/components/ui/filter-select-chip";
import { cn } from "@/lib/utils";

export const ALL_OPTION_VALUE = "__all__";

export interface FilterOption {
  value: string;
  label: string;
}

export interface FilterDefinition {
  id: string;
  label: string;
  value: string | undefined;
  options: readonly FilterOption[];
  onChange: (value: string | undefined) => void;
  defaultLabel?: string;
  emptyMessage?: string;
}

interface FilterBarProps {
  searchValue: string;
  searchPlaceholder: string;
  onSearchChange: (value: string) => void;
  filters: FilterDefinition[];
  trailing?: React.ReactNode;
  className?: string;
}

export function FilterBar({
  searchValue,
  searchPlaceholder,
  onSearchChange,
  filters,
  trailing,
  className,
}: FilterBarProps) {
  const activeFilters = filters.filter((filter) => filter.value !== undefined);
  const hasActiveState = activeFilters.length > 0 || searchValue.length > 0;

  const clearAll = () => {
    onSearchChange("");
    for (const filter of activeFilters) {
      filter.onChange(undefined);
    }
  };

  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      <div className="relative w-full sm:w-72">
        <MagnifyingGlassIcon
          className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden="true"
        />
        <Input
          value={searchValue}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder={searchPlaceholder}
          className="h-9 pr-8 pl-9"
          aria-label={searchPlaceholder}
        />
        {searchValue ? (
          <button
            type="button"
            onClick={() => onSearchChange("")}
            aria-label="Clear search"
            className="absolute top-1/2 right-2 inline-flex size-5 -translate-y-1/2 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
          >
            <XIcon className="size-3.5" aria-hidden="true" />
          </button>
        ) : null}
      </div>

      {filters.map((filter) => (
        <FilterSelectChip
          key={filter.id}
          label={filter.label}
          value={filter.value ?? ALL_OPTION_VALUE}
          disabled={filter.options.length === 0 && filter.value === undefined}
          options={[
            {
              label: filter.defaultLabel ?? `All ${filter.label.toLowerCase()}`,
              value: ALL_OPTION_VALUE,
            },
            ...filter.options,
          ]}
          onValueChange={(value) =>
            filter.onChange(value === ALL_OPTION_VALUE ? undefined : value)
          }
        />
      ))}

      {hasActiveState ? (
        <Button
          variant="ghost"
          size="sm"
          className="h-8 text-muted-foreground"
          onClick={clearAll}
        >
          Clear filters
        </Button>
      ) : null}

      {trailing ? <div className="ml-auto">{trailing}</div> : null}
    </div>
  );
}
