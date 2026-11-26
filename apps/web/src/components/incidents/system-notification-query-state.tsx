// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  WarningIcon,
  ArrowsClockwiseIcon,
} from "@phosphor-icons/react/dist/ssr";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getErrorMessage } from "@/lib/utils";

interface SystemNotificationQueryStateProps {
  error: unknown;
  hasNotificationsPage: boolean;
  isError: boolean;
  isFetching: boolean;
  isInitialLoading: boolean;
  onRetry: () => void;
}

function NotificationLoadingSkeleton() {
  return (
    <div className="space-y-3 rounded-lg border bg-card p-4">
      <Skeleton className="h-9 w-full max-w-sm" />
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, index) => (
          <Skeleton className="h-10 w-full" key={index} />
        ))}
      </div>
    </div>
  );
}

/** Presents initial loading and recoverable notification API failures. */
export function SystemNotificationQueryState({
  error,
  hasNotificationsPage,
  isError,
  isFetching,
  isInitialLoading,
  onRetry,
}: SystemNotificationQueryStateProps) {
  if (isInitialLoading) {
    return <NotificationLoadingSkeleton />;
  }

  if (!isError) {
    return null;
  }

  return (
    <Alert variant="warning">
      <WarningIcon aria-hidden />
      <AlertTitle>
        {hasNotificationsPage
          ? "Notification updates are delayed"
          : "Notifications are temporarily unavailable"}
      </AlertTitle>
      <AlertDescription className="mt-1 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          {hasNotificationsPage
            ? "Showing the last available results while automatic recovery continues in the background."
            : `${getErrorMessage(error, "We could not load notifications.")} Automatic recovery will continue in the background.`}
        </span>
        <Button
          className="shrink-0 self-start sm:self-auto"
          disabled={isFetching}
          onClick={onRetry}
          size="sm"
          type="button"
          variant="outline"
        >
          <ArrowsClockwiseIcon
            className={isFetching ? "animate-spin" : undefined}
          />
          {isFetching ? "Retrying" : "Retry now"}
        </Button>
      </AlertDescription>
    </Alert>
  );
}
