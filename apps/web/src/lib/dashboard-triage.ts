// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export interface AlertTriageState {
  severity: string;
  unread: boolean;
}

export interface DeploymentReviewMetrics {
  failed: number;
}

const HIGH_PRIORITY_ALERT_SEVERITIES = new Set(["CRITICAL", "WARNING"]);

export function getHighPriorityUnreadAlerts<T extends AlertTriageState>(
  alerts: readonly T[],
): T[] {
  return alerts.filter(
    (alert) =>
      alert.unread && HIGH_PRIORITY_ALERT_SEVERITIES.has(alert.severity),
  );
}

export function getDeploymentReviewCount({
  failed,
}: DeploymentReviewMetrics): number {
  return failed;
}
