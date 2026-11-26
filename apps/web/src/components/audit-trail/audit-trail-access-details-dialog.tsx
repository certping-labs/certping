// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import {
  ACCESS_REFERENCE_LABEL,
  accessReference,
} from "@/components/audit-trail/audit-trail-access-columns";
import {
  EventTime,
  ResultBadge,
} from "@/components/audit-trail/audit-trail-columns";
import { Field } from "@/components/audit-trail/audit-trail-details-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { AuditTrailAccessSource } from "@/lib/audit-trail-source";
import type { AuditTrailAccessEntry } from "@/types/audit-trail";

interface AuditTrailAccessDetailsDialogProps {
  source: Pick<AuditTrailAccessSource, "codeLabel" | "activityLabel"> & {
    copy: Pick<AuditTrailAccessSource["copy"], "target">;
  };
  entry: AuditTrailAccessEntry | null;
  onClose: () => void;
  /** Narrows the log to the reads of the entry's user. */
  onShowUser: (userId: number) => void;
}

export function AuditTrailAccessDetailsDialog({
  source,
  entry,
  onClose,
  onShowUser,
}: AuditTrailAccessDetailsDialogProps) {
  const reference = entry ? accessReference(entry) : undefined;
  const userId = entry?.userId;
  return (
    <Dialog open={entry !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        {entry ? (
          <>
            <DialogHeader>
              <DialogTitle className="pr-6">
                {source.activityLabel(entry.activity)}
              </DialogTitle>
              <DialogDescription>
                <EventTime value={entry.timestamp} />
              </DialogDescription>
            </DialogHeader>

            <dl className="grid gap-4 sm:grid-cols-2">
              <Field label="Result">
                <span className="flex flex-wrap items-center gap-2">
                  <ResultBadge
                    status={entry.status}
                    codeLabel={source.codeLabel}
                  />
                  {entry.errorCode ? (
                    <span className="font-mono text-[13px] text-muted-foreground">
                      {entry.errorCode}
                    </span>
                  ) : null}
                </span>
              </Field>
              {entry.target ? (
                <Field label={source.copy.target} mono>
                  {entry.target}
                </Field>
              ) : null}
              <Field label="User">
                {entry.actor}
                {userId !== undefined ? (
                  <span className="block text-xs text-muted-foreground">
                    User ID {userId}
                  </span>
                ) : null}
              </Field>
              {entry.ipAddress ? (
                <Field label="IP address" mono>
                  {entry.ipAddress}
                </Field>
              ) : null}
              {reference ? (
                <Field label={ACCESS_REFERENCE_LABEL} mono>
                  {reference}
                </Field>
              ) : null}
            </dl>

            {userId !== undefined ? (
              <div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => onShowUser(userId)}
                >
                  Show this user&apos;s activity
                </Button>
              </div>
            ) : null}
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
