// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import type { ColumnDef } from "@tanstack/react-table";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { humanizeEnum } from "@/lib/humanize";
import {
  formatNotificationDateTime,
  getNotificationEventLabel,
  getNotificationRecipientLabel,
  getNotificationStatusBadgeVariant,
  getNotificationStatusBadgeLabel,
} from "@/lib/incidents/notification-presentation";
import type { NotificationRecord } from "@/types/notifications";

export function NotificationStatusBadge({
  status,
}: {
  status: string | null | undefined;
}) {
  return (
    <Badge
      variant={getNotificationStatusBadgeVariant(status ?? "unknown")}
      textOnly
      className="whitespace-nowrap"
    >
      {getNotificationStatusBadgeLabel(status)}
    </Badge>
  );
}

export const getNotificationDelivery = (notification: NotificationRecord) =>
  [
    humanizeEnum(notification.integrationType ?? "system"),
    notification.source ?? notification.sentBy,
  ]
    .filter(Boolean)
    .join(" · ");

export function createNotificationColumns(
  onViewNotification: (notification: NotificationRecord) => void,
): ColumnDef<NotificationRecord>[] {
  return [
    {
      id: "subject",
      header: "Event",
      size: 320,
      cell: ({ row }) => (
        <p className="font-medium text-foreground">
          {getNotificationEventLabel(row.original)}
        </p>
      ),
    },
    {
      id: "recipientSummary",
      accessorKey: "recipientSummary",
      header: "Recipients",
      size: 280,
      cell: ({ row }) => (
        <span className="line-clamp-2 text-muted-foreground">
          {getNotificationRecipientLabel(row.original)}
        </span>
      ),
    },
    {
      id: "delivery",
      header: "Delivery",
      size: 220,
      cell: ({ row }) => (
        <span className="text-muted-foreground">
          {getNotificationDelivery(row.original)}
        </span>
      ),
    },
    {
      id: "status",
      accessorKey: "status",
      header: "Status",
      size: 110,
      cell: ({ row }) => (
        <NotificationStatusBadge status={row.original.status} />
      ),
    },
    {
      id: "createdAt",
      accessorKey: "createdAt",
      header: "Sent",
      size: 170,
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-muted-foreground">
          {formatNotificationDateTime(row.original.createdAt)}
        </span>
      ),
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      size: 80,
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button
            variant="ghost"
            size="sm"
            aria-label={`View ${getNotificationEventLabel(row.original)}`}
            onClick={(event) => {
              event.stopPropagation();
              onViewNotification(row.original);
            }}
          >
            View
          </Button>
        </div>
      ),
    },
  ];
}
