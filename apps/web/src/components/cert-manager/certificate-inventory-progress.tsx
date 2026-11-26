// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { WarningIcon, CircleNotchIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";

interface CertificateInventoryProgressProps {
  readonly isLoading: boolean;
  readonly hasError: boolean;
  readonly loadedItems: number;
  readonly totalItems: number;
  readonly onRetry: () => void;
  readonly inventoryLabel?: string;
  readonly itemLabel?: string;
}

export function CertificateInventoryProgress({
  isLoading,
  hasError,
  loadedItems,
  totalItems,
  onRetry,
  inventoryLabel = "certificate inventory",
  itemLabel = "certificates",
}: CertificateInventoryProgressProps) {
  if (!isLoading && !hasError) {
    return null;
  }

  if (hasError) {
    return (
      <div
        className="flex flex-col gap-3 rounded-lg border border-[hsl(var(--warning)/0.35)] bg-[hsl(var(--warning)/0.08)] px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
        role="alert"
      >
        <div className="flex min-w-0 items-start gap-2.5">
          <WarningIcon className="mt-0.5 size-4 shrink-0 text-[hsl(var(--warning-700))]" />
          <div>
            <p className="text-sm font-medium">Inventory partially loaded</p>
            <p className="text-xs leading-5 text-muted-foreground">
              Showing {loadedItems.toLocaleString()} of approximately{" "}
              {totalItems.toLocaleString()} {itemLabel}. Retry to load the
              remaining records.
            </p>
          </div>
        </div>
        <Button
          className="shrink-0"
          size="sm"
          variant="outline"
          onClick={onRetry}
        >
          Retry remaining
        </Button>
      </div>
    );
  }

  const progressValue =
    totalItems > 0 ? Math.min((loadedItems / totalItems) * 100, 100) : 0;
  const accessibleInventoryLabel =
    inventoryLabel.charAt(0).toUpperCase() + inventoryLabel.slice(1);

  return (
    <div
      className="rounded-lg border border-border bg-muted/35 px-4 py-3"
      role="status"
      aria-live="polite"
    >
      <div className="flex items-center justify-between gap-4 text-xs">
        <div className="flex min-w-0 items-center gap-2 text-foreground">
          <CircleNotchIcon className="size-4 shrink-0 animate-spin text-primary" />
          <span className="font-medium">Loading {inventoryLabel}</span>
        </div>
        <span className="shrink-0 text-muted-foreground tabular-nums">
          {loadedItems.toLocaleString()} of {totalItems.toLocaleString()}
        </span>
      </div>
      <Progress
        aria-label={`${accessibleInventoryLabel} loading progress`}
        className="mt-2 h-1.5"
        value={progressValue}
      />
    </div>
  );
}
