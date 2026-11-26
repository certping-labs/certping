// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { CircleNotchIcon } from "@phosphor-icons/react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import type { BulkDeleteProgress } from "@/hooks/use-bulk-delete-certificates";
import {
  formatBulkDeleteProgress,
  getBulkDeleteConfirmation,
} from "@/lib/cert-manager/bulk-certificate-delete";

/**
 * Confirms a bulk delete and shows its progress. It stays open while the run
 * goes (Delete is disabled, so it cannot be sent twice); closing it mid-run
 * stops the run, which is why Cancel reads "Stop" then.
 */
export function BulkDeleteCertificatesDialog({
  open,
  domainCount,
  progress,
  onConfirm,
  onClose,
}: {
  open: boolean;
  domainCount: number;
  progress: BulkDeleteProgress | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const { title, description } = getBulkDeleteConfirmation(domainCount);
  const isRunning = progress !== null;

  return (
    <AlertDialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) onClose();
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        {isRunning ? (
          <p
            role="status"
            className="flex items-center gap-2 text-sm text-muted-foreground"
          >
            <CircleNotchIcon
              className="h-4 w-4 animate-spin motion-reduce:animate-none"
              aria-hidden
            />
            {formatBulkDeleteProgress(progress.settledCount, progress.total)}
          </p>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel>{isRunning ? "Stop" : "Cancel"}</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            disabled={isRunning}
            onClick={(event) => {
              // Stay open to show progress; the page closes it when the run ends.
              event.preventDefault();
              onConfirm();
            }}
          >
            {domainCount === 1 ? "Delete domain" : "Delete domains"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
