// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useMemo } from "react";

import { SystemNotificationCardGrid } from "@/components/incidents/system-notification-card-grid";
import { createNotificationColumns } from "@/components/incidents/system-notification-table";
import { CustomTable } from "@/components/ui/custom-table";
import { FilterSelectChip } from "@/components/ui/filter-select-chip";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import { getNotificationStatusLabel } from "@/lib/incidents/notification-presentation";
import {
  ALL_NOTIFICATION_STATUSES,
  NOTIFICATION_STATUSES,
  type NotificationPage,
  type NotificationRecord,
  type NotificationStatus,
  type NotificationStatusFilter,
} from "@/types/notifications";

interface SystemNotificationsListProps {
  readonly notificationsPage: NotificationPage | undefined;
  readonly isFetching: boolean;
  readonly page: number;
  readonly pageSize: number;
  readonly statusFilter: NotificationStatusFilter;
  readonly onPageChange: (page: number) => void;
  readonly onPageSizeChange: (pageSize: number) => void;
  readonly onStatusFilterChange: (status: NotificationStatusFilter) => void;
  readonly onViewNotification: (notification: NotificationRecord) => void;
}

const NOTIFICATION_PAGE_SIZE_OPTIONS = [10, 20, 50, 100] as const;
const NOTIFICATION_SEARCH_KEYS = [
  "subject",
  "recipientSummary",
  "templateName",
  "notificationAction",
  "notificationType",
  "source",
  "status",
];
const STATUS_OPTIONS = [
  { label: "All statuses", value: "all" },
  ...NOTIFICATION_STATUSES.map((status) => ({
    label: getNotificationStatusLabel(status),
    value: status,
  })),
];
const NO_NOTIFICATIONS: NotificationRecord[] = [];
const getNotificationId = (row: NotificationRecord) => row.id;

const isNotificationStatus = (value: string): value is NotificationStatus =>
  NOTIFICATION_STATUSES.some((status) => status === value);

export function SystemNotificationsList({
  notificationsPage,
  isFetching,
  page,
  pageSize,
  statusFilter,
  onPageChange,
  onPageSizeChange,
  onStatusFilterChange,
  onViewNotification,
}: SystemNotificationsListProps) {
  const [viewMode, setViewMode] = useResponsiveViewMode({
    storageKey: "system-notifications_view",
  });
  const notifications = notificationsPage?.items ?? NO_NOTIFICATIONS;
  const columns = useMemo(
    () => createNotificationColumns(onViewNotification),
    [onViewNotification],
  );
  const renderGrid = useCallback(
    (rows: NotificationRecord[]) => (
      <SystemNotificationCardGrid
        notifications={rows}
        onViewNotification={onViewNotification}
      />
    ),
    [onViewNotification],
  );
  const handleStatusChange = (value: string): void => {
    if (value === "all") onStatusFilterChange(ALL_NOTIFICATION_STATUSES);
    else if (isNotificationStatus(value)) onStatusFilterChange(value);
  };

  return (
    <CustomTable
      viewSwitcher={{ value: viewMode, onValueChange: setViewMode }}
      renderGrid={renderGrid}
      columns={columns}
      data={notifications}
      searchBy={NOTIFICATION_SEARCH_KEYS}
      searchPlaceholder="Search this page..."
      emptyTableMsg="No system notifications found."
      showColumnVisibility={false}
      denseRows
      getRowId={getNotificationId}
      onRowClick={onViewNotification}
      toolbarFilters={
        <>
          <FilterSelectChip
            label="Status"
            value={
              statusFilter === ALL_NOTIFICATION_STATUSES ? "all" : statusFilter
            }
            options={STATUS_OPTIONS}
            onValueChange={handleStatusChange}
            disabled={isFetching}
          />
          {isFetching ? (
            <span role="status" className="text-xs text-muted-foreground">
              Refreshing notifications…
            </span>
          ) : null}
        </>
      }
      serverPagination={{
        page: notificationsPage?.page ?? page,
        totalPages: notificationsPage?.totalPages ?? 0,
        pageSize: notificationsPage?.size ?? pageSize,
        pageSizeOptions: NOTIFICATION_PAGE_SIZE_OPTIONS,
        totalElements: notificationsPage?.totalElements ?? 0,
        disabled: isFetching,
        onPageChange,
        onPageSizeChange,
      }}
    />
  );
}
