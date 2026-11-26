// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { ColumnDef } from "@tanstack/react-table";

import {
  EventTime,
  ResultBadge,
} from "@/components/audit-trail/audit-trail-columns";
import type { AuditTrailAccessSource } from "@/lib/audit-trail-source";
import type { AuditTrailAccessEntry } from "@/types/audit-trail";

/** What the id a customer quotes is called, as on the Activity view. */
export const ACCESS_REFERENCE_LABEL = "Request ID";

/**
 * The id a customer quotes to support for a read: its request id, else (an
 * entry written without one) the flow's correlation id.
 */
export const accessReference = (
  entry: AuditTrailAccessEntry,
): string | undefined => entry.requestId || entry.correlationId;

const timeColumn: ColumnDef<AuditTrailAccessEntry> = {
  accessorKey: "timestamp",
  header: "Time",
  size: 170,
  cell: ({ row }) => <EventTime value={row.original.timestamp} />,
};

const userColumn: ColumnDef<AuditTrailAccessEntry> = {
  id: "user",
  header: "User",
  size: 240,
  cell: ({ row }) => (
    <div className="min-w-0">
      <p
        className="truncate text-sm text-foreground"
        title={row.original.actor}
      >
        {row.original.actor}
      </p>
      {row.original.ipAddress ? (
        <p className="truncate font-mono text-xs text-muted-foreground">
          {row.original.ipAddress}
        </p>
      ) : null}
    </div>
  ),
};

type AccessColumnSource = Pick<
  AuditTrailAccessSource,
  "codeLabel" | "activityLabel"
> & { copy: Pick<AuditTrailAccessSource["copy"], "target"> };

/** A source's read columns. */
export const createAuditTrailAccessColumns = (
  source: AccessColumnSource,
): ColumnDef<AuditTrailAccessEntry>[] => {
  const activityColumn: ColumnDef<AuditTrailAccessEntry> = {
    accessorKey: "activity",
    header: "Activity",
    size: 190,
    cell: ({ row }) => (
      <p className="truncate text-sm font-medium text-foreground">
        {source.activityLabel(row.original.activity)}
      </p>
    ),
  };

  const targetColumn: ColumnDef<AuditTrailAccessEntry> = {
    id: "target",
    header: source.copy.target,
    size: 240,
    cell: ({ row }) =>
      row.original.target ? (
        <p
          className="truncate font-mono text-[13px] text-foreground"
          title={row.original.target}
        >
          {row.original.target}
        </p>
      ) : // Nothing named: an empty cell rather than "None".
      null,
  };

  const resultColumn: ColumnDef<AuditTrailAccessEntry> = {
    accessorKey: "status",
    header: "Result",
    size: 110,
    cell: ({ row }) => (
      <ResultBadge status={row.original.status} codeLabel={source.codeLabel} />
    ),
  };

  const referenceColumn: ColumnDef<AuditTrailAccessEntry> = {
    id: "reference",
    header: ACCESS_REFERENCE_LABEL,
    size: 230,
    cell: ({ row }) => {
      const value = accessReference(row.original);
      return value ? (
        <p
          className="truncate font-mono text-xs text-muted-foreground"
          title={value}
        >
          {value}
        </p>
      ) : null;
    },
  };

  return [
    timeColumn,
    userColumn,
    activityColumn,
    targetColumn,
    resultColumn,
    referenceColumn,
  ];
};
