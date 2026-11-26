// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { type MouseEvent } from "react";
import Link from "next/link";
import type { ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNowStrict } from "date-fns";
import {
  CheckCircleIcon,
  ClockIcon,
  PowerIcon,
  XCircleIcon,
} from "@phosphor-icons/react";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import { AuditTrailCopyId } from "@/components/audit-trail/audit-trail-copy-id";
import { Badge } from "@/components/ui/badge";
import type {
  AuditTrailColumnId,
  AuditTrailSource,
} from "@/lib/audit-trail-source";
import {
  cn,
  formatDateTimeDetailed,
  formatDateTimeWithSeconds,
  parseDateValue,
} from "@/lib/utils";
import type { AuditTrailEntry } from "@/types/audit-trail";

/** Below this the table scrolls sideways instead of squeezing cells into wraps. */
export const AUDIT_TRAIL_TABLE_MIN_WIDTH_CLASS = "min-w-[1080px]";

/** The classic columns, for a source that names none. */
const CLASSIC_COLUMNS: readonly AuditTrailColumnId[] = [
  "time",
  "actor",
  "action",
  "resource",
  "result",
  "details",
];
const CLASSIC_PLATFORM_COLUMNS: readonly AuditTrailColumnId[] = [
  "time",
  "actor",
  "organization",
  "action",
  "resource",
  "result",
  "details",
];

/** The columns a source shows on a view. */
export const auditTrailColumnIds = (
  source: Pick<AuditTrailSource, "columns">,
  platform: boolean,
): readonly AuditTrailColumnId[] =>
  source.columns?.[platform ? "platform" : "customer"] ??
  (platform ? CLASSIC_PLATFORM_COLUMNS : CLASSIC_COLUMNS);

/**
 * "5 minutes ago"; "just now" for a time ahead of this device's clock (the
 * server's runs a little ahead of some); empty when the time does not parse.
 */
export const relativeTime = (value: string): string => {
  const date = parseDateValue(value);
  if (!date) {
    return "";
  }
  return date.getTime() >= Date.now()
    ? "just now"
    : formatDistanceToNowStrict(date, { addSuffix: true });
};

type CodeLabel = (code: string) => string;

const RESULT_BADGES: Readonly<
  Record<
    string,
    { variant: "success" | "destructive" | "warning"; icon: PhosphorIcon }
  >
> = {
  SUCCESS: { variant: "success", icon: CheckCircleIcon },
  FAILURE: { variant: "destructive", icon: XCircleIcon },
  PENDING: { variant: "warning", icon: ClockIcon },
};

export const actorLabel = (
  entry: AuditTrailEntry,
  codeLabel: CodeLabel,
): string => entry.actorName || entry.userEmail || codeLabel(entry.actorType);

const SYSTEM_ACTOR_PREFIX = "system:";

/** The job behind a system row, which the platform route names as "system:<job>". */
const systemJob = (entry: AuditTrailEntry): string | undefined =>
  entry.actor?.startsWith(SYSTEM_ACTOR_PREFIX)
    ? entry.actor.slice(SYSTEM_ACTOR_PREFIX.length)
    : undefined;

/** Who a row's actor is beyond its name: the job, and the user CertPing acted for. */
export const actorDetail = (
  entry: AuditTrailEntry,
  codeLabel: CodeLabel,
): string => {
  const job = systemJob(entry);
  const onBehalf =
    entry.actorType === "SYSTEM" && entry.userEmail
      ? `for ${entry.userEmail}`
      : undefined;
  return [job ?? codeLabel(entry.actorType), onBehalf]
    .filter(Boolean)
    .join(" ");
};

const keepRowClosed = (event: MouseEvent) => event.stopPropagation();

export const requestLine = (entry: AuditTrailEntry): string | undefined =>
  entry.request
    ? `${entry.request.method} ${entry.request.route} · ${entry.request.status} · ${entry.request.durationMs} ms`
    : undefined;

export function ResultBadge({
  status,
  codeLabel,
}: {
  status: string;
  codeLabel: CodeLabel;
}) {
  const badge = RESULT_BADGES[status];
  if (!badge) {
    return <Badge variant="secondary">{codeLabel(status)}</Badge>;
  }
  const Icon = badge.icon;
  return (
    <Badge variant={badge.variant}>
      <Icon className="h-3 w-3" aria-hidden />
      {codeLabel(status)}
    </Badge>
  );
}

/** How long ago, with the exact time beneath and the full date on hover. */
export function EventWhen({ value }: { value: string }) {
  return (
    <div className="min-w-0">
      <time
        dateTime={value}
        title={formatDateTimeDetailed(value)}
        className="block truncate text-sm text-foreground"
      >
        {relativeTime(value)}
      </time>
      <p className="truncate text-xs text-muted-foreground tabular-nums">
        {formatDateTimeWithSeconds(value)}
      </p>
    </div>
  );
}

/** Marks an event of a feature that is off for the organization now. */
export function FeatureOffBadge() {
  return (
    <Badge
      variant="secondary"
      title="This feature isn't available now. The event happened while it was on."
    >
      <PowerIcon className="h-3 w-3" aria-hidden />
      Feature off
    </Badge>
  );
}

export function EventTime({ value }: { value: string }) {
  return (
    <time
      dateTime={value}
      title={formatDateTimeDetailed(value)}
      className="text-[13px] whitespace-nowrap text-foreground tabular-nums"
    >
      {formatDateTimeWithSeconds(value)}
    </time>
  );
}

const timeColumn: ColumnDef<AuditTrailEntry> = {
  accessorKey: "timestamp",
  header: "Time",
  size: 170,
  cell: ({ row }) => <EventTime value={row.original.timestamp} />,
};

const organizationColumn: ColumnDef<AuditTrailEntry> = {
  id: "organization",
  header: "Organization",
  size: 170,
  cell: ({ row }) => (
    <p
      className="truncate text-sm text-foreground"
      title={row.original.organizationName ?? undefined}
    >
      {row.original.organizationName ??
        (row.original.organizationId
          ? `#${row.original.organizationId}`
          : "Platform")}
    </p>
  ),
};

const detailsColumn: ColumnDef<AuditTrailEntry> = {
  accessorKey: "summary",
  header: "Details",
  size: 300,
  cell: ({ row }) => {
    const request = requestLine(row.original);
    return (
      <div className="min-w-0">
        <p
          className="line-clamp-2 text-sm text-muted-foreground"
          title={row.original.summary}
        >
          {row.original.summary}
        </p>
        {request ? (
          <p
            className="truncate font-mono text-xs text-muted-foreground"
            title={request}
          >
            {request}
          </p>
        ) : null}
      </div>
    );
  },
};

type ColumnSource = Pick<
  AuditTrailSource,
  | "codeLabel"
  | "resourceLabel"
  | "resourceHref"
  | "columns"
  | "failureLine"
  | "actorDetail"
  | "categoryLabel"
> & { copy: Pick<AuditTrailSource["copy"], "resource"> };

/** Who a row's actor is beyond their name, as the source says it. */
export const sourceActorDetail = (
  source: Pick<AuditTrailSource, "codeLabel" | "actorDetail">,
  entry: AuditTrailEntry,
): string | undefined =>
  source.actorDetail
    ? source.actorDetail(entry)
    : actorDetail(entry, source.codeLabel);

function EventCell({
  entry,
  source,
  onOpen,
}: {
  entry: AuditTrailEntry;
  source: ColumnSource;
  onOpen?: (entry: AuditTrailEntry) => void;
}) {
  const failure = source.failureLine?.(entry);
  const category = entry.category
    ? (source.categoryLabel?.(entry.category) ??
      source.codeLabel(entry.category))
    : undefined;
  const summaryClassName =
    // A long name in the sentence (an id-like resource name) breaks anywhere
    // rather than widening the cell.
    "line-clamp-2 text-left text-sm font-medium text-foreground wrap-anywhere";
  return (
    <div className="min-w-0 space-y-1 py-1.5">
      {onOpen ? (
        <button
          type="button"
          // Where focus returns when the entry's details close.
          data-audit-trail-open={entry.id}
          onClick={(event) => {
            event.stopPropagation();
            onOpen(entry);
          }}
          className={cn(
            summaryClassName,
            "rounded-sm underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden",
          )}
        >
          {entry.summary}
        </button>
      ) : (
        <p className={summaryClassName}>{entry.summary}</p>
      )}
      {failure ? (
        <p className="text-xs wrap-anywhere status-danger-text">
          {failure}
          {entry.errorCode ? (
            <span className="ml-1.5 font-mono text-[11px] text-muted-foreground">
              {entry.errorCode}
            </span>
          ) : null}
        </p>
      ) : null}
      {category || entry.featureOff ? (
        <div className="flex flex-wrap items-center gap-1.5">
          {category ? (
            <span className="text-xs text-muted-foreground">{category}</span>
          ) : null}
          {entry.featureOff ? <FeatureOffBadge /> : null}
        </div>
      ) : null}
      <p className="truncate text-xs text-muted-foreground lg:hidden">
        {actorLabel(entry, source.codeLabel)} · {relativeTime(entry.timestamp)}
      </p>
    </div>
  );
}

/**
 * A source's event columns, in the order the source names them; the classic
 * set without. `onOpen` makes the event's sentence a button that opens it,
 * so a keyboard reaches what a click on the row opens.
 */
export const createAuditTrailColumns = (
  source: ColumnSource,
  platform: boolean,
  onOpen?: (entry: AuditTrailEntry) => void,
): ColumnDef<AuditTrailEntry>[] => {
  const { codeLabel, resourceLabel, resourceHref } = source;

  const actorColumn: ColumnDef<AuditTrailEntry> = {
    id: "actor",
    header: "Actor",
    size: 200,
    meta: source.columns ? { className: "hidden lg:table-cell" } : undefined,
    cell: ({ row }) => {
      const detail = sourceActorDetail(source, row.original);
      const name = actorLabel(row.original, codeLabel);
      return (
        <div className="min-w-0">
          <p className="truncate text-sm text-foreground" title={name}>
            {name}
          </p>
          {detail ? (
            <p
              className="truncate text-xs text-muted-foreground"
              title={detail}
            >
              {detail}
            </p>
          ) : null}
        </div>
      );
    },
  };

  const actionColumn: ColumnDef<AuditTrailEntry> = {
    accessorKey: "action",
    header: "Action",
    size: 170,
    cell: ({ row }) => (
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-foreground">
          {codeLabel(row.original.action)}
        </p>
        {row.original.visibility === "INTERNAL" ? (
          <p className="text-xs text-muted-foreground">Internal</p>
        ) : null}
      </div>
    ),
  };

  const resourceColumn: ColumnDef<AuditTrailEntry> = {
    id: "resource",
    header: source.copy.resource,
    size: 200,
    cell: ({ row }) => {
      const href = resourceHref?.(row.original, platform);
      return (
        <div className="min-w-0">
          {row.original.resourceName ? (
            <p
              className="truncate font-mono text-[13px] text-foreground"
              title={row.original.resourceName}
            >
              {row.original.resourceName}
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">None</p>
          )}
          {href ? (
            <Link
              href={href}
              onClick={keepRowClosed}
              className="block truncate text-xs font-medium text-primary underline-offset-4 hover:underline"
            >
              {resourceLabel(row.original)}
            </Link>
          ) : (
            <p className="truncate text-xs text-muted-foreground">
              {resourceLabel(row.original)}
            </p>
          )}
        </div>
      );
    },
  };

  const resultColumn: ColumnDef<AuditTrailEntry> = {
    accessorKey: "status",
    header: "Result",
    size: source.columns ? 112 : 110,
    meta: source.columns ? { className: "hidden sm:table-cell" } : undefined,
    cell: ({ row }) => (
      <ResultBadge status={row.original.status} codeLabel={codeLabel} />
    ),
  };

  const eventColumn: ColumnDef<AuditTrailEntry> = {
    accessorKey: "summary",
    id: "event",
    header: "Event",
    // No width of its own: the fixed-layout table gives it what the sized
    // columns leave, which they leave plenty of by dropping out on narrow
    // screens, so the sentence never pushes the table wider than its card.
    meta: { fluid: true },
    cell: ({ row }) => (
      <EventCell entry={row.original} source={source} onOpen={onOpen} />
    ),
  };

  const referenceColumn: ColumnDef<AuditTrailEntry> = {
    id: "reference",
    header: "Request ID",
    // A 20-character id whole beside its copy button; longer ones are
    // shortened from the middle.
    size: 216,
    // The platform view also shows the organization, so it shows ids wider.
    meta: {
      className: platform ? "hidden 2xl:table-cell" : "hidden xl:table-cell",
    },
    cell: ({ row }) =>
      row.original.requestId ? (
        <AuditTrailCopyId label="request ID" value={row.original.requestId} />
      ) : (
        <span className="text-xs text-muted-foreground">None</span>
      ),
  };

  const whenColumn: ColumnDef<AuditTrailEntry> = {
    accessorKey: "timestamp",
    id: "when",
    header: "Time",
    // Room for "Oct 10, 2026, 12:59:00 PM" beside the cell's padding.
    size: 184,
    meta: { className: "hidden sm:table-cell" },
    cell: ({ row }) => <EventWhen value={row.original.timestamp} />,
  };

  const byId: Record<AuditTrailColumnId, ColumnDef<AuditTrailEntry>> = {
    time: timeColumn,
    actor: actorColumn,
    organization: source.columns
      ? { ...organizationColumn, meta: { className: "hidden xl:table-cell" } }
      : organizationColumn,
    action: actionColumn,
    resource: resourceColumn,
    result: resultColumn,
    details: detailsColumn,
    event: eventColumn,
    reference: referenceColumn,
    when: whenColumn,
  };
  return auditTrailColumnIds(source, platform).map((id) => byId[id]);
};
