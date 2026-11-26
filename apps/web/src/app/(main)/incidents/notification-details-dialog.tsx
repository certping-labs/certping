// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  SUPPRESSED_NOTIFICATION_STATUS,
  getNotificationReasonLabel,
  getNotificationStatusLabel,
} from "@/lib/incidents/notification-presentation";
import { formatDateTimeDetailed } from "@/lib/utils";
import type { NotificationRecord } from "@/types/notifications";

interface NotificationDetailsDialogProps {
  notification: NotificationRecord | null;
  isOpen: boolean;
  onClose: () => void;
}

const formatNotificationLabel = (value: string | null | undefined): string =>
  value
    ? value
        .toLowerCase()
        .replaceAll("_", " ")
        .replace(/\b\w/g, (character) => character.toUpperCase())
    : "Unknown";

export function NotificationDetailsDialog({
  notification,
  isOpen,
  onClose,
}: NotificationDetailsDialogProps) {
  if (!notification) {
    return null;
  }

  const reason = getNotificationReasonLabel(notification);
  const suppressed = notification.status === SUPPRESSED_NOTIFICATION_STATUS;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-h-[80vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-xl font-semibold">
            Event Details
          </DialogTitle>
          <p className="text-sm text-muted-foreground">
            {formatDateTimeDetailed(notification.createdAt)}
          </p>
        </DialogHeader>

        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary" textOnly className="text-xs">
              {notification.integrationType ?? "System"}
            </Badge>
            <Badge variant="secondary" textOnly className="text-xs">
              {getNotificationStatusLabel(notification.status)}
            </Badge>
            <Badge variant="secondary" textOnly className="text-xs">
              {formatNotificationLabel(notification.notificationType)}
            </Badge>
          </div>

          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-foreground">Subject</h3>
            <p className="rounded-md border bg-muted px-3 py-2 text-sm text-foreground">
              {notification.subject ?? "No subject"}
            </p>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">
                Recipients
              </h3>
              <div className="rounded-md border bg-muted px-3 py-2 text-sm text-foreground">
                {notification.recipients.length > 0 ? (
                  <div className="space-y-1">
                    {notification.recipients.map((recipient) => (
                      <p key={recipient}>{recipient}</p>
                    ))}
                  </div>
                ) : (
                  <p>{notification.email ?? "No recipients"}</p>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">Source</h3>
              <div className="rounded-md border bg-muted px-3 py-2 text-sm text-foreground">
                <p>{notification.source ?? notification.sentBy ?? "Unknown"}</p>
              </div>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">
                Notification Action
              </h3>
              <p className="rounded-md border bg-muted px-3 py-2 text-sm text-foreground">
                {formatNotificationLabel(notification.notificationAction)}
              </p>
            </div>

            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">
                Template
              </h3>
              <p className="rounded-md border bg-muted px-3 py-2 text-sm text-foreground">
                {notification.templateName ?? "N/A"}
              </p>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">
                Request ID
              </h3>
              <p className="rounded-md border bg-muted px-3 py-2 font-mono text-sm break-all text-foreground">
                {notification.requestId ?? "N/A"}
              </p>
            </div>

            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">
                Message ID
              </h3>
              <p className="rounded-md border bg-muted px-3 py-2 font-mono text-sm break-all text-foreground">
                {notification.messageId ?? "N/A"}
              </p>
            </div>

            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">Sent At</h3>
              <p className="rounded-md border bg-muted px-3 py-2 text-sm text-foreground">
                {formatDateTimeDetailed(notification.sentAt)}
              </p>
            </div>
          </div>

          {notification.roles.length > 0 ? (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">Roles</h3>
              <div className="flex flex-wrap gap-2">
                {notification.roles.map((role) => (
                  <Badge key={role} variant="secondary" textOnly>
                    {role}
                  </Badge>
                ))}
              </div>
            </div>
          ) : null}

          {reason ? (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-foreground">
                {suppressed ? "Why it wasn't sent" : "Failure Reason"}
              </h3>
              <p className="rounded-md border bg-muted px-3 py-2 text-sm whitespace-pre-wrap text-foreground">
                {reason}
              </p>
            </div>
          ) : null}

          <div className="flex justify-end pt-2">
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
