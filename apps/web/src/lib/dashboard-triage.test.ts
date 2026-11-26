// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  getDeploymentReviewCount,
  getHighPriorityUnreadAlerts,
} from "@/lib/dashboard-triage";

describe("dashboard-triage", () => {
  it("keeps only unread warning and critical alerts in dashboard triage", () => {
    expect(
      getHighPriorityUnreadAlerts([
        { id: "read-critical", severity: "CRITICAL", unread: false },
        { id: "unread-info", severity: "INFO", unread: true },
        { id: "unread-warning", severity: "WARNING", unread: true },
        { id: "unread-critical", severity: "CRITICAL", unread: true },
      ]),
    ).toEqual([
      { id: "unread-warning", severity: "WARNING", unread: true },
      { id: "unread-critical", severity: "CRITICAL", unread: true },
    ]);
  });

  it("treats failed deployments as deployment review work", () => {
    expect(getDeploymentReviewCount({ failed: 5 })).toBe(5);
  });
});
