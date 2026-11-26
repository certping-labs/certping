// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { type FormEvent, useState } from "react";
import { MagnifyingGlassIcon, XIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { DateRangePicker } from "@/components/ui/date-range-picker";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { platformVisibility } from "@/lib/audit-trail-filters";
import type { AuditTrailSource } from "@/lib/audit-trail-source";
import {
  AUDIT_TRAIL_ALL_VISIBILITIES,
  AUDIT_TRAIL_VISIBILITIES,
  type AuditTrailFilters,
} from "@/types/audit-trail";

const ALL = "all";
const VISIBILITY_CHOICES = [
  ...AUDIT_TRAIL_VISIBILITIES,
  AUDIT_TRAIL_ALL_VISIBILITIES,
] as const;

interface AuditTrailFilterBarProps {
  source: Pick<AuditTrailSource, "codeLabel" | "codes"> & {
    filters: Pick<AuditTrailSource["filters"], "has">;
    copy: Pick<AuditTrailSource["copy"], "resourceFilter" | "datePlaceholder">;
  };
  filters: AuditTrailFilters;
  actions: readonly string[];
  resources: readonly string[];
  platform: boolean;
  rangeError?: string;
  onChange: (filters: AuditTrailFilters) => void;
}

interface CodeSelectProps {
  label: string;
  allLabel: string;
  value?: string;
  codes: readonly string[];
  /** How a code reads. */
  labelOf: (code: string) => string;
  onChange: (value: string | undefined) => void;
}

export function CodeSelect({
  label,
  allLabel,
  value,
  codes,
  labelOf,
  onChange,
}: CodeSelectProps) {
  // A code from a link can be one the options list does not hold yet.
  const options = value && !codes.includes(value) ? [value, ...codes] : codes;
  return (
    <Select
      value={value ?? ALL}
      onValueChange={(next) => onChange(next === ALL ? undefined : next)}
    >
      <SelectTrigger aria-label={label} className="h-9 w-full sm:w-44">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{allLabel}</SelectItem>
        {options.map((code) => (
          <SelectItem key={code} value={code}>
            {labelOf(code)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function TextFilter({
  label,
  placeholder,
  value,
  inputMode,
  onCommit,
}: {
  label: string;
  placeholder: string;
  value?: string;
  inputMode?: "numeric";
  onCommit: (value: string | undefined) => void;
}) {
  const [draft, setDraft] = useState(value ?? "");
  const [committed, setCommitted] = useState(value);
  // Follow the URL when it changes underneath, e.g. on "Clear filters".
  if (committed !== value) {
    setCommitted(value);
    setDraft(value ?? "");
  }
  const commit = () => {
    const next = draft.trim() || undefined;
    if (next !== value) {
      onCommit(next);
    }
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    commit();
  };

  return (
    <form role="search" onSubmit={submit} className="relative w-full sm:w-60">
      <MagnifyingGlassIcon
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground"
      />
      <Input
        aria-label={label}
        value={draft}
        inputMode={inputMode}
        placeholder={placeholder}
        onChange={(event) => setDraft(event.target.value)}
        onBlur={commit}
        className="h-9 pl-9"
      />
    </form>
  );
}

export function AuditTrailFilterBar({
  source,
  filters,
  actions,
  resources,
  platform,
  rangeError,
  onChange,
}: AuditTrailFilterBarProps) {
  const { codeLabel, codes } = source;
  const set = (key: keyof AuditTrailFilters, value: string | undefined) =>
    onChange({ ...filters, [key]: value });

  return (
    <div className="space-y-2">
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
        <TextFilter
          label={source.copy.resourceFilter.label}
          placeholder={source.copy.resourceFilter.placeholder}
          value={filters.resourceName}
          onCommit={(value) => set("resourceName", value)}
        />
        {platform ? (
          <>
            <TextFilter
              label="Organization ID"
              placeholder="Organization ID"
              inputMode="numeric"
              value={filters.organizationId}
              onCommit={(value) => set("organizationId", value)}
            />
            <TextFilter
              label="Correlation ID"
              placeholder="Correlation ID"
              value={filters.correlationId}
              onCommit={(value) => set("correlationId", value)}
            />
            <TextFilter
              label="Request ID"
              placeholder="Request ID"
              value={filters.requestId}
              onCommit={(value) => set("requestId", value)}
            />
          </>
        ) : null}
        <CodeSelect
          label="Action"
          allLabel="All actions"
          value={filters.action}
          codes={actions}
          labelOf={codeLabel}
          onChange={(value) => set("action", value)}
        />
        <CodeSelect
          label="Resource"
          allLabel="All resources"
          value={filters.resourceType}
          codes={resources}
          labelOf={codeLabel}
          onChange={(value) => set("resourceType", value)}
        />
        <CodeSelect
          label="Result"
          allLabel="All results"
          value={filters.status}
          codes={codes.results}
          labelOf={codeLabel}
          onChange={(value) => set("status", value)}
        />
        <CodeSelect
          label="Actor"
          allLabel="All actors"
          value={filters.actorType}
          codes={codes.actorTypes}
          labelOf={codeLabel}
          onChange={(value) => set("actorType", value)}
        />
        {platform ? (
          <Select
            value={platformVisibility(filters.visibility)}
            onValueChange={(value) =>
              set(
                "visibility",
                value === platformVisibility(undefined) ? undefined : value,
              )
            }
          >
            <SelectTrigger
              aria-label="Visibility"
              className="h-9 w-full sm:w-44"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {VISIBILITY_CHOICES.map((choice) => (
                <SelectItem key={choice} value={choice}>
                  {codeLabel(choice)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : null}
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
        {filters.resourceId ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() => set("resourceId", undefined)}
            aria-label={`Stop filtering by resource ID ${filters.resourceId}`}
          >
            Resource ID {filters.resourceId}
            <XIcon />
          </Button>
        ) : null}
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
