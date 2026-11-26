// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { BadgeProps } from "@/components/ui/badge";
import { humanizeEnum } from "@/lib/humanize";
import { notificationCategoryLabel } from "@/lib/notification-settings";
import { formatDateTime } from "@/lib/utils";
import type { NotificationRecord } from "@/types/notifications";

export const formatNotificationDateTime = (
  value: string | null | undefined,
): string => {
  const formatted = formatDateTime(value ?? null);
  return formatted === "-" ? "N/A" : formatted;
};

export const getNotificationStatusBadgeVariant = (
  status: string,
): BadgeProps["variant"] => {
  const normalized = status.toLowerCase();
  if (
    normalized.includes("success") ||
    normalized.includes("issued") ||
    normalized.includes("active") ||
    normalized.includes("delivered")
  ) {
    return "success";
  }
  if (
    normalized.includes("fail") ||
    normalized.includes("error") ||
    normalized.includes("invalid")
  ) {
    return "destructive";
  }
  if (normalized.includes("pending") || normalized.includes("processing")) {
    return "warning";
  }
  return "secondary";
};

/** The notifier's status of a notification an organization turned off. */
export const SUPPRESSED_NOTIFICATION_STATUS = "SUPPRESSED";
const SUPPRESSED_REASON_PREFIX = "ORG_PREFERENCE:";

/** How a delivery status reads in full; SUPPRESSED names the notification settings. */
export const getNotificationStatusLabel = (
  status: string | null | undefined,
): string => {
  if (status === SUPPRESSED_NOTIFICATION_STATUS) {
    return "Not sent: turned off in notification settings";
  }
  return humanizeEnum(status) || "Unknown";
};

/** A status short enough for a one-line badge; the details dialog says why. */
export const getNotificationStatusBadgeLabel = (
  status: string | null | undefined,
): string =>
  status === SUPPRESSED_NOTIFICATION_STATUS
    ? "Not sent"
    : getNotificationStatusLabel(status);

/**
 * Why a notification was not sent, in words: a suppressed one names the
 * category that was turned off; any other reason reads as the notifier wrote it.
 */
export const getNotificationReasonLabel = (
  notification: Pick<NotificationRecord, "status" | "failureReason">,
): string | null => {
  const reason = notification.failureReason;
  if (notification.status === SUPPRESSED_NOTIFICATION_STATUS) {
    return reason?.startsWith(SUPPRESSED_REASON_PREFIX)
      ? `${notificationCategoryLabel(reason.slice(SUPPRESSED_REASON_PREFIX.length))} is turned off in notification settings.`
      : "This notification is turned off in notification settings.";
  }
  return reason || null;
};

export const getNotificationEventLabel = (
  notification: NotificationRecord,
): string =>
  notification.subject ??
  notification.notificationAction ??
  notification.templateName ??
  "No subject";

export const getNotificationRecipientLabel = (
  notification: NotificationRecord,
): string =>
  notification.recipients.slice(0, 2).join(", ") +
    (notification.recipients.length > 2
      ? ` + ${notification.recipients.length - 2} more`
      : "") ||
  notification.recipientSummary ||
  notification.email ||
  "-";
