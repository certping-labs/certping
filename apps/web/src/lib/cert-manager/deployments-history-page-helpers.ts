// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { DeploymentRecord } from "@/types/cert-manager";

export function formatDeploymentStatusLabel(value: string): string {
  return value
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function getDeploymentStatusBadgeClass(status: string): string {
  switch (status.toUpperCase()) {
    case "SUCCESS":
    case "COMPLETED":
      return "status-success-text";
    case "FAILED":
    case "FAILED_VALIDATION":
    case "FAILED_DEPLOYMENT":
      return "status-danger-text";
    case "PENDING":
    case "IN_PROGRESS":
    case "DEPLOYING":
      return "status-warning-text";
    default:
      return "text-muted-foreground";
  }
}

export function parsePositiveInteger(value: string | null): number | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

export function buildDeploymentRequestHref(
  userDomainCertificateId: string,
  requestId: string,
): string {
  return `/cert-manager/deployments/${encodeURIComponent(userDomainCertificateId)}/${encodeURIComponent(requestId)}`;
}

export type DeploymentStatusGroup = "pending" | "failed" | "";

export function filterDeploymentsByStatusGroup(
  deployments: DeploymentRecord[],
  statusGroup: string,
): DeploymentRecord[] {
  const normalizedGroup = statusGroup.trim().toLowerCase();

  return deployments.filter((deployment) => {
    const normalizedStatus = deployment.status.toUpperCase();
    return normalizedGroup === "pending"
      ? ["PENDING", "IN_PROGRESS", "DEPLOYING"].includes(normalizedStatus)
      : normalizedGroup === "failed"
        ? normalizedStatus.startsWith("FAILED")
        : true;
  });
}

export function computeDeploymentMetrics(deployments: DeploymentRecord[]): {
  total: number;
  success: number;
  failed: number;
  pending: number;
} {
  let success = 0;
  let failed = 0;
  let pending = 0;

  for (const deployment of deployments) {
    const status = deployment.status.toUpperCase();
    if (status === "SUCCESS" || status === "COMPLETED") {
      success += 1;
    } else if (status.startsWith("FAILED")) {
      failed += 1;
    } else if (
      status === "PENDING" ||
      status === "IN_PROGRESS" ||
      status === "DEPLOYING"
    ) {
      pending += 1;
    }
  }

  return {
    total: deployments.length,
    success,
    failed,
    pending,
  };
}
