// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import {
  getNotificationDelivery,
  NotificationStatusBadge,
} from "@/components/incidents/system-notification-table";
import { Button } from "@/components/ui/button";
import {
  formatNotificationDateTime,
  getNotificationEventLabel,
  getNotificationRecipientLabel,
} from "@/lib/incidents/notification-presentation";
import type { NotificationRecord } from "@/types/notifications";

interface SystemNotificationCardGridProps {
  readonly notifications: NotificationRecord[];
  readonly onViewNotification: (notification: NotificationRecord) => void;
}

export function SystemNotificationCardGrid({
  notifications,
  onViewNotification,
}: SystemNotificationCardGridProps) {
  if (notifications.length === 0) {
    return (
      <p className="rounded-xl border border-dashed border-border px-6 py-10 text-center text-sm text-muted-foreground">
        No system notifications found on this page.
      </p>
    );
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {notifications.map((notification) => (
        <article
          key={notification.id}
          className="min-w-0 space-y-4 rounded-xl border border-border bg-card p-4 text-left"
        >
          <div className="flex items-start justify-between gap-3">
            <p className="min-w-0 flex-1 font-medium text-foreground">
              {getNotificationEventLabel(notification)}
            </p>
            <NotificationStatusBadge status={notification.status} />
          </div>
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <div className="col-span-2 min-w-0">
              <dt className="text-xs text-muted-foreground">Recipients</dt>
              <dd className="mt-1 truncate text-foreground">
                {getNotificationRecipientLabel(notification)}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">Delivery</dt>
              <dd className="mt-1 truncate text-foreground">
                {getNotificationDelivery(notification)}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">Timestamp</dt>
              <dd className="mt-1 text-foreground">
                {formatNotificationDateTime(notification.createdAt)}
              </dd>
            </div>
          </dl>
          <div className="flex justify-end">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onViewNotification(notification)}
            >
              View
            </Button>
          </div>
        </article>
      ))}
    </div>
  );
}
