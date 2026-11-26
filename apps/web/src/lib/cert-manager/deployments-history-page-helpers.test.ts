// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  buildDeploymentRequestHref,
  computeDeploymentMetrics,
  filterDeploymentsByStatusGroup,
  formatDeploymentStatusLabel,
  getDeploymentStatusBadgeClass,
  parsePositiveInteger,
} from "@/lib/cert-manager/deployments-history-page-helpers";
import type { DeploymentRecord } from "@/types/cert-manager";

function makeDeployment(
  overrides: Partial<DeploymentRecord>,
): DeploymentRecord {
  return {
    requestId: "req-1",
    status: "SUCCESS",
    domain: "example.com",
    createdAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  } as DeploymentRecord;
}

describe("deployments-history-page-helpers", () => {
  it("formats status labels into Title Case", () => {
    expect(formatDeploymentStatusLabel("FAILED_DEPLOYMENT")).toBe(
      "Failed Deployment",
    );
    expect(formatDeploymentStatusLabel("SUCCESS")).toBe("Success");
  });

  it("maps deployment status to badge class", () => {
    expect(getDeploymentStatusBadgeClass("success")).toBe(
      "status-success-text",
    );
    expect(getDeploymentStatusBadgeClass("COMPLETED")).toBe(
      "status-success-text",
    );
    expect(getDeploymentStatusBadgeClass("FAILED_VALIDATION")).toBe(
      "status-danger-text",
    );
    expect(getDeploymentStatusBadgeClass("DEPLOYING")).toBe(
      "status-warning-text",
    );
    expect(getDeploymentStatusBadgeClass("UNKNOWN")).toBe(
      "text-muted-foreground",
    );
  });

  it("parses positive integers from query values", () => {
    expect(parsePositiveInteger(null)).toBeUndefined();
    expect(parsePositiveInteger("")).toBeUndefined();
    expect(parsePositiveInteger("0")).toBeUndefined();
    expect(parsePositiveInteger("-1")).toBeUndefined();
    expect(parsePositiveInteger("10")).toBe(10);
    expect(parsePositiveInteger("10px")).toBe(10);
  });

  it("builds encoded deployment request href", () => {
    expect(buildDeploymentRequestHref("user/1", "req#1")).toBe(
      "/cert-manager/deployments/user%2F1/req%231",
    );
  });

  it("filters deployments by status group", () => {
    const deployments = [
      makeDeployment({ status: "PENDING" }),
      makeDeployment({ status: "IN_PROGRESS" }),
      makeDeployment({ status: "DEPLOYING" }),
      makeDeployment({ status: "FAILED" }),
      makeDeployment({ status: "FAILED_VALIDATION" }),
      makeDeployment({ status: "SUCCESS" }),
    ];

    expect(filterDeploymentsByStatusGroup(deployments, "pending")).toHaveLength(
      3,
    );
    expect(
      filterDeploymentsByStatusGroup(deployments, " failed "),
    ).toHaveLength(2);
    expect(filterDeploymentsByStatusGroup(deployments, "")).toHaveLength(6);
  });

  it("computes metrics over normalized statuses", () => {
    const metrics = computeDeploymentMetrics([
      makeDeployment({ status: "SUCCESS" }),
      makeDeployment({ status: "COMPLETED" }),
      makeDeployment({ status: "FAILED_DEPLOYMENT" }),
      makeDeployment({ status: "PENDING" }),
      makeDeployment({ status: "IN_PROGRESS" }),
      makeDeployment({ status: "DEPLOYING" }),
      makeDeployment({ status: "CAPTURED" }),
    ]);

    expect(metrics).toEqual({
      total: 7,
      success: 2,
      failed: 1,
      pending: 3,
    });
  });
});
