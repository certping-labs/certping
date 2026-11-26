// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useEffect, useState } from "react";
import { ShieldWarningIcon } from "@phosphor-icons/react";

import { NotificationDetailsDialog } from "@/app/(main)/incidents/notification-details-dialog";
import { SystemNotificationQueryState } from "@/components/incidents/system-notification-query-state";
import { SystemNotificationsList } from "@/components/incidents/system-notifications-list";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { useSystemNotifications } from "@/hooks/incidents";
import { useAuth } from "@/hooks/use-auth";
import { canViewNotifications } from "@/lib/authz";
import { isAccessDeniedError } from "@/lib/http-errors";
import {
  ALL_NOTIFICATION_STATUSES,
  type NotificationRecord,
  type NotificationStatusFilter,
} from "@/types/notifications";

export default function SystemNotificationsPage() {
  const { user, isLoading: isLoadingAuth } = useAuth();
  const canViewAlerts = canViewNotifications(user);

  const [selectedNotification, setSelectedNotification] =
    useState<NotificationRecord | null>(null);
  const [notificationDialogOpen, setNotificationDialogOpen] = useState(false);
  const [accessDeniedByScope, setAccessDeniedByScope] = useState<
    Record<string, boolean>
  >({});

  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(20);
  const [statusFilter, setStatusFilter] = useState<NotificationStatusFilter>(
    ALL_NOTIFICATION_STATUSES,
  );
  const accessScopeKey = `${canViewAlerts ? "1" : "0"}:${user?.id ?? "anon"}`;
  const apiAccessDenied = Boolean(accessDeniedByScope[accessScopeKey]);

  const notificationsQuery = useSystemNotifications(
    {
      page,
      size: pageSize,
      ...(statusFilter === ALL_NOTIFICATION_STATUSES
        ? {}
        : { status: statusFilter }),
    },
    { enabled: canViewAlerts && !apiAccessDenied, poll: true },
  );

  const notificationsPage = notificationsQuery.data;

  useEffect(() => {
    if (
      notificationsPage &&
      notificationsPage.totalPages > 0 &&
      page >= notificationsPage.totalPages
    ) {
      setPage(notificationsPage.totalPages - 1);
    }
  }, [notificationsPage, page]);

  useEffect(() => {
    if (!canViewAlerts || apiAccessDenied) {
      return;
    }

    const queryError =
      notificationsQuery.error ?? notificationsQuery.failureReason;
    if (isAccessDeniedError(queryError)) {
      setAccessDeniedByScope((previous) => {
        if (previous[accessScopeKey]) {
          return previous;
        }
        return {
          ...previous,
          [accessScopeKey]: true,
        };
      });
    }
  }, [
    accessScopeKey,
    apiAccessDenied,
    canViewAlerts,
    notificationsQuery.error,
    notificationsQuery.failureReason,
  ]);

  const handleStatusFilterChange = (status: NotificationStatusFilter): void => {
    setStatusFilter(status);
    setPage(0);
  };

  const handlePageSizeChange = (size: number): void => {
    setPageSize(size);
    setPage(0);
  };

  const openNotificationDialog = useCallback(
    (notification: NotificationRecord): void => {
      setSelectedNotification(notification);
      setNotificationDialogOpen(true);
    },
    [],
  );

  const closeNotificationDialog = (): void => {
    setNotificationDialogOpen(false);
    setSelectedNotification(null);
  };

  const queryError =
    notificationsQuery.error ?? notificationsQuery.failureReason;
  const isInitialLoading =
    notificationsQuery.isLoading && notificationsQuery.failureCount === 0;
  const hasRecoverableError =
    (notificationsQuery.isError || notificationsQuery.failureCount > 0) &&
    !isAccessDeniedError(queryError);

  if (isLoadingAuth) {
    return (
      <div className="flex h-[60vh] items-center justify-center">
        <Skeleton className="h-8 w-8 rounded-full" />
      </div>
    );
  }

  if (!canViewAlerts || apiAccessDenied) {
    return (
      <div className="p-6">
        <Alert variant="warning" className="mx-auto max-w-md">
          <ShieldWarningIcon aria-hidden />
          <AlertTitle>Access restricted</AlertTitle>
          <AlertDescription>
            You do not have permission to view system notifications.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <>
      <div className="w-full space-y-5 p-4 sm:p-6">
        <PageHeader
          title="System notifications"
          subtitle="Every email and message CertPing sent, and whether it was delivered."
        />

        <SystemNotificationQueryState
          error={queryError}
          hasNotificationsPage={Boolean(notificationsPage)}
          isError={hasRecoverableError}
          isFetching={notificationsQuery.isFetching}
          isInitialLoading={isInitialLoading}
          onRetry={() => void notificationsQuery.refetch()}
        />

        {!isInitialLoading ? (
          <SystemNotificationsList
            notificationsPage={notificationsPage}
            isFetching={notificationsQuery.isFetching}
            page={page}
            pageSize={pageSize}
            statusFilter={statusFilter}
            onPageChange={setPage}
            onPageSizeChange={handlePageSizeChange}
            onStatusFilterChange={handleStatusFilterChange}
            onViewNotification={openNotificationDialog}
          />
        ) : null}
      </div>

      <NotificationDetailsDialog
        notification={selectedNotification}
        isOpen={notificationDialogOpen}
        onClose={closeNotificationDialog}
      />
    </>
  );
}
