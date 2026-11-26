// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { SystemAlert } from "@/hooks/incidents";
import { getAlertTypeLabel } from "@/lib/alerts";
import { EnvelopeOpenIcon } from "@phosphor-icons/react";
import { formatDateTimeDetailed } from "@/lib/utils";
import { SupportReferenceLink } from "@/components/support/support-reference-link";
import { AlertStatusBadge } from "./alert-status-badge";

interface AlertDetailsDialogProps {
  alert: SystemAlert | null;
  isOpen: boolean;
  canEscalate: boolean;
  canMarkAsRead: boolean;
  hasEscalations: boolean;
  isMarkingAsRead: boolean;
  onClose: () => void;
  onMarkAsRead: (alert: SystemAlert) => void;
  onEscalate: (alert: SystemAlert) => void;
  onViewEscalations: (alert: SystemAlert) => void;
}

const getAlertTarget = (alert: SystemAlert): string | null => alert.domain;

const getMessage = (alert: SystemAlert): string =>
  alert.message || "No message available";

export function AlertDetailsDialog({
  alert,
  isOpen,
  canEscalate,
  canMarkAsRead,
  hasEscalations,
  isMarkingAsRead,
  onClose,
  onEscalate,
  onMarkAsRead,
  onViewEscalations,
}: AlertDetailsDialogProps) {
  if (!alert) {
    return null;
  }

  const target = getAlertTarget(alert);

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-h-[80vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-xl font-semibold">
            Alert Details
          </DialogTitle>
          <DialogDescription>
            {formatDateTimeDetailed(alert.createdAt)}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              variant={
                alert.severity === "CRITICAL"
                  ? "destructive"
                  : alert.severity === "WARNING"
                    ? "warning"
                    : alert.severity === "INFO"
                      ? "info"
                      : "secondary"
              }
              textOnly
              className="text-xs"
            >
              {alert.severity}
            </Badge>
            <Badge
              variant="secondary"
              textOnly
              className="text-xs text-muted-foreground"
            >
              {getAlertTypeLabel(alert.alertType)}
            </Badge>
            {alert.unread && (
              <span className="relative flex h-2 w-2">
                <span className="relative inline-flex h-2 w-2 rounded-full bg-primary"></span>
              </span>
            )}
          </div>

          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-foreground">Target</h3>
            <p className="rounded-md border bg-muted px-3 py-2 font-mono text-sm break-all text-foreground">
              {target ?? "Not provided"}
            </p>
          </div>

          {alert.status ? (
            <div className="flex flex-col items-start justify-start gap-2 space-y-2">
              <h3 className="text-sm font-semibold text-foreground">Status</h3>
              <AlertStatusBadge status={alert.status} className="text-xs" />
            </div>
          ) : null}

          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-foreground">
              What happened
            </h3>
            <p className="rounded-md border bg-muted px-3 py-2 text-sm whitespace-pre-wrap text-foreground">
              {getMessage(alert)}
            </p>
            {alert.severity !== "INFO" ? (
              <SupportReferenceLink
                correlationId={alert.correlationId}
                summary={`${getAlertTypeLabel(alert.alertType)}${alert.domain ? ` for ${alert.domain}` : ""}`}
                message={alert.message}
                domain={alert.domain}
              />
            ) : null}
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
            {canEscalate && (
              <Button
                variant="outline"
                className="gap-2"
                onClick={() =>
                  hasEscalations ? onViewEscalations(alert) : onEscalate(alert)
                }
              >
                {hasEscalations ? "View escalations" : "Escalate"}
              </Button>
            )}
            {canMarkAsRead && alert.unread && (
              <Button
                className="gap-2"
                disabled={isMarkingAsRead}
                onClick={() => onMarkAsRead(alert)}
              >
                <EnvelopeOpenIcon className="h-4 w-4" />
                Mark as Read
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
