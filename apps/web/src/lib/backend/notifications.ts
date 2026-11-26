// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import type {
  NotificationFilters,
  NotificationPage,
  NotificationRecord,
} from "@/types/notifications";

export const DEFAULT_NOTIFICATION_PAGE_SIZE = 20;
export const MAX_NOTIFICATION_PAGE_SIZE = 100;

interface NotificationApiRecord {
  id: number | string;
  userId: number | null;
  organizationId: number | string | null;
  websiteId: number | string | null;
  requestId: string | null;
  email: string | null;
  recipients: string[] | null;
  templateName: string | null;
  subject: string | null;
  sentBy: string | null;
  integrationType: string | null;
  status: string | null;
  notificationType: string | null;
  notificationAction: string | null;
  source: string | null;
  roles: string[] | null;
  failureReason: string | null;
  sentAt: string | null;
  createdAt: string;
  updatedAt: string | null;
  messageId: string | null;
}

interface NotificationsApiResponse {
  success: boolean;
  message: string;
  data: NotificationApiRecord[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

const uniqueStrings = (values: readonly string[]): string[] =>
  Array.from(new Set(values));

const toNotificationRecord = (
  notification: NotificationApiRecord,
): NotificationRecord => {
  // The server no longer sends payloadJson; every field below comes from
  // the record's own columns.
  const recipients = uniqueStrings(notification.recipients ?? []);
  const email = notification.email ?? recipients[0] ?? null;

  return {
    ...notification,
    id: String(notification.id),
    organizationId:
      notification.organizationId === null
        ? null
        : String(notification.organizationId),
    websiteId:
      notification.websiteId === null ? null : String(notification.websiteId),
    email,
    recipients,
    recipientSummary: recipients.length > 0 ? recipients.join(", ") : email,
    notificationType: notification.notificationType ?? null,
    notificationAction: notification.notificationAction ?? null,
    source: notification.source ?? notification.sentBy ?? null,
    roles: uniqueStrings(notification.roles ?? []),
  };
};

const normalizePage = (page: number | undefined): number =>
  typeof page === "number" && Number.isInteger(page) && page >= 0 ? page : 0;

const normalizePageSize = (size: number | undefined): number => {
  if (typeof size !== "number" || !Number.isInteger(size) || size <= 0) {
    return DEFAULT_NOTIFICATION_PAGE_SIZE;
  }

  return Math.min(size, MAX_NOTIFICATION_PAGE_SIZE);
};

/** Retrieves one server-paginated page of organization-scoped notifications. */
export async function getSystemNotifications(
  filters: NotificationFilters = {},
): Promise<NotificationPage> {
  const page = normalizePage(filters.page);
  const size = normalizePageSize(filters.size);
  const response = await apiClient.get<NotificationsApiResponse>(
    apiRoutes.query.incidents.notifications,
    {
      params: {
        page,
        size,
        ...(filters.status ? { status: filters.status } : {}),
      },
    },
  );

  return {
    items: response.data.data.map(toNotificationRecord),
    page: response.data.page,
    size: response.data.size,
    totalElements: response.data.totalElements,
    totalPages: response.data.totalPages,
  };
}
