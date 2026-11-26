// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export type CertificateAlertType = "CERTIFICATE_FAILURE" | "DEPLOYMENT_FAILURE";

export type AlertType = CertificateAlertType;

export type AlertSeverity = "CRITICAL" | "WARNING" | "INFO";

export const ALERT_TYPE_LABELS: Record<AlertType, string> = {
  CERTIFICATE_FAILURE: "Certificate failure",
  DEPLOYMENT_FAILURE: "Deployment failure",
};

export const getAlertTypeLabel = (alertType: AlertType | undefined): string =>
  alertType
    ? (ALERT_TYPE_LABELS[alertType] ?? alertType.replaceAll("_", " "))
    : "Alert";

/** INFO alerts are good news; only unread problems warrant a red dot. */
export const hasUnreadProblem = (
  alerts: ReadonlyArray<{ unread: boolean; severity: string }> | undefined,
): boolean =>
  alerts?.some((alert) => alert.unread && alert.severity !== "INFO") ?? false;

/** The service that owns an alert; it is part of an alert's key and its deep links (`ssl:<id>`). */
export type AlertSource = "ssl";

export const getAlertKey = (alert: {
  source: AlertSource;
  id: string;
}): string => `${alert.source}:${alert.id}`;
