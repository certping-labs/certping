// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export const NOTIFICATION_STATUSES = [
  "PENDING",
  "SENT",
  "DELIVERED",
  "FAILED",
  "READ",
  "SUPPRESSED",
] as const;

export type NotificationStatus = (typeof NOTIFICATION_STATUSES)[number];
export const ALL_NOTIFICATION_STATUSES = "ALL";
export type NotificationStatusFilter =
  typeof ALL_NOTIFICATION_STATUSES | NotificationStatus;

export interface NotificationFilters {
  readonly page?: number;
  readonly size?: number;
  readonly status?: NotificationStatus;
}

export interface NotificationRecord {
  readonly id: string;
  readonly userId: number | null;
  readonly organizationId: string | null;
  readonly websiteId: string | null;
  readonly requestId: string | null;
  readonly email: string | null;
  readonly recipients: string[];
  readonly recipientSummary: string | null;
  readonly templateName: string | null;
  readonly subject: string | null;
  readonly sentBy: string | null;
  readonly integrationType: string | null;
  readonly status: string | null;
  readonly notificationType: string | null;
  readonly notificationAction: string | null;
  readonly source: string | null;
  readonly roles: string[];
  readonly failureReason: string | null;
  readonly sentAt: string | null;
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
  readonly messageId: string | null;
}

export interface NotificationPage {
  readonly items: NotificationRecord[];
  readonly page: number;
  readonly size: number;
  readonly totalElements: number;
  readonly totalPages: number;
}
