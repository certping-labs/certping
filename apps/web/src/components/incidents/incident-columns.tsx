// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import type { ColumnDef, FilterFn } from "@tanstack/react-table";
import {
  ArrowSquareOutIcon,
  EnvelopeIcon,
  EnvelopeOpenIcon,
} from "@phosphor-icons/react/dist/ssr";

import {
  EmptyCell,
  formatIncidentDateTime,
  getAlertMessage,
  getAlertTarget,
  getEscalationReference,
  getProviderLabel,
  SeverityBadge,
} from "@/components/incidents/alert-presentation";
import { AlertStatusBadge } from "@/app/(main)/incidents/alert-status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { SystemAlert } from "@/hooks/incidents";
import { getAlertTypeLabel } from "@/lib/alerts";
import type { IncidentHistoryItem } from "@/types/integrations";

export interface AlertActions {
  escalationCount: (alert: SystemAlert) => number;
  canMarkRead: (alert: SystemAlert) => boolean;
  canEscalate: (alert: SystemAlert) => boolean;
  isMarking: boolean;
  onOpen: (alert: SystemAlert) => void;
  onMarkRead: (alert: SystemAlert) => void;
  onEscalate: (alert: SystemAlert) => void;
  onViewEscalations: (alertId: number) => void;
}

const selectFilter =
  (read: (value: unknown) => string | undefined): FilterFn<SystemAlert> =>
  (row, columnId, filterValue: string) =>
    !filterValue ||
    filterValue === "all" ||
    read(row.getValue(columnId)) === filterValue;

const asString = (value: unknown) =>
  typeof value === "string" ? value : undefined;
const asReadFlag = (value: unknown) => (value ? "true" : "false");

const stop =
  (action: () => void) =>
  (event: React.MouseEvent): void => {
    event.stopPropagation();
    action();
  };

export function AlertRowActions({
  alert,
  actions,
  layout = "row",
}: {
  alert: SystemAlert;
  actions: AlertActions;
  layout?: "row" | "card";
}) {
  const escalations = actions.escalationCount(alert);
  const grow = layout === "card" ? "flex-1" : undefined;
  return (
    <div
      className={
        layout === "card"
          ? "flex flex-wrap gap-2"
          : "flex items-center justify-end gap-1.5"
      }
    >
      {actions.canMarkRead(alert) ? (
        <Button
          variant="ghost"
          size="iconSm"
          disabled={!alert.unread || actions.isMarking}
          aria-label={alert.unread ? "Mark as read" : "Already read"}
          onClick={stop(() => actions.onMarkRead(alert))}
        >
          {alert.unread ? (
            <EnvelopeIcon className="text-primary" aria-hidden />
          ) : (
            <EnvelopeOpenIcon className="text-muted-foreground" aria-hidden />
          )}
        </Button>
      ) : null}
      {escalations > 0 ? (
        <Button
          variant="outline"
          size="sm"
          className={grow}
          onClick={stop(() =>
            actions.onViewEscalations(Number.parseInt(alert.id, 10)),
          )}
        >
          View {escalations} escalation{escalations === 1 ? "" : "s"}
        </Button>
      ) : actions.canEscalate(alert) ? (
        <Button
          variant="outline"
          size="sm"
          className={grow}
          onClick={stop(() => actions.onEscalate(alert))}
        >
          Escalate
        </Button>
      ) : null}
    </div>
  );
}

export function createAlertColumns(
  actions: AlertActions,
): ColumnDef<SystemAlert>[] {
  return [
    {
      id: "target",
      header: "Incident",
      size: 240,
      cell: ({ row }) => (
        <div className="flex min-w-0 flex-col gap-0.5">
          <button
            type="button"
            onClick={stop(() => actions.onOpen(row.original))}
            className="w-fit max-w-full truncate rounded-sm text-left font-medium text-foreground underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
          >
            {getAlertTarget(row.original)}
          </button>
          <span className="text-sm text-muted-foreground">
            {getAlertTypeLabel(row.original.alertType)}
          </span>
        </div>
      ),
    },
    {
      id: "message",
      header: "Message",
      size: 300,
      cell: ({ row }) => (
        <p className="line-clamp-1 text-muted-foreground">
          {getAlertMessage(row.original)}
        </p>
      ),
    },
    {
      id: "severity",
      accessorKey: "severity",
      header: "Severity",
      size: 100,
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      id: "status",
      accessorKey: "status",
      header: "Status",
      size: 110,
      cell: ({ row }) =>
        row.original.status ? (
          <AlertStatusBadge
            status={row.original.status}
            className="whitespace-nowrap"
          />
        ) : (
          <EmptyCell label="No status" />
        ),
    },
    {
      id: "createdAt",
      accessorKey: "createdAt",
      header: "Raised",
      size: 170,
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-muted-foreground">
          {formatIncidentDateTime(row.original.createdAt)}
        </span>
      ),
    },
    {
      id: "source",
      accessorKey: "source",
      header: "Source",
      filterFn: selectFilter(asString),
      cell: () => null,
    },
    {
      id: "unread",
      accessorKey: "unread",
      header: "Read status",
      filterFn: selectFilter(asReadFlag),
      cell: () => null,
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      size: 160,
      cell: ({ row }) => (
        <AlertRowActions alert={row.original} actions={actions} />
      ),
    },
  ];
}

export function createEscalationColumns(
  actorFor: (incident: IncidentHistoryItem) => string,
): ColumnDef<IncidentHistoryItem>[] {
  return [
    {
      id: "summary",
      accessorKey: "summary",
      header: "Summary",
      size: 360,
      cell: ({ row }) => (
        <p className="font-medium text-foreground">
          {row.original.summary || "No summary"}
        </p>
      ),
    },
    {
      id: "provider",
      accessorKey: "provider",
      header: "Provider",
      size: 140,
      cell: ({ row }) => (
        <Badge variant="secondary" textOnly>
          {getProviderLabel(row.original.provider)}
        </Badge>
      ),
    },
    {
      id: "reference",
      accessorKey: "externalReference",
      header: "Reference",
      size: 170,
      cell: ({ row }) => (
        <span className="font-mono text-[13px] text-foreground">
          {getEscalationReference(row.original)}
        </span>
      ),
    },
    {
      id: "actorUserId",
      accessorKey: "actorUserId",
      header: "Raised by",
      size: 160,
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {actorFor(row.original)}
        </span>
      ),
    },
    {
      id: "createdAt",
      accessorKey: "createdAt",
      header: "Raised",
      size: 180,
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-muted-foreground">
          {formatIncidentDateTime(row.original.createdAt)}
        </span>
      ),
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      size: 80,
      cell: ({ row }) =>
        row.original.externalUrl ? (
          <div className="flex justify-end">
            <Button asChild variant="ghost" size="iconSm">
              <a
                href={row.original.externalUrl}
                rel="noreferrer"
                target="_blank"
                aria-label={`Open in ${getProviderLabel(row.original.provider)}`}
              >
                <ArrowSquareOutIcon aria-hidden />
              </a>
            </Button>
          </div>
        ) : null,
    },
  ];
}
