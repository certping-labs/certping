// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getAlertKey, getAlertTypeLabel, hasUnreadProblem } from "@/lib/alerts";

describe("alerts", () => {
  it("labels certificate types and degrades gracefully", () => {
    expect(getAlertTypeLabel("CERTIFICATE_FAILURE")).toBe(
      "Certificate failure",
    );
    expect(getAlertTypeLabel("DEPLOYMENT_FAILURE")).toBe("Deployment failure");
    expect(getAlertTypeLabel(undefined)).toBe("Alert");
  });

  it("counts only unread non-INFO alerts as problems", () => {
    expect(hasUnreadProblem(undefined)).toBe(false);
    expect(hasUnreadProblem([{ unread: true, severity: "INFO" }])).toBe(false);
    expect(hasUnreadProblem([{ unread: false, severity: "CRITICAL" }])).toBe(
      false,
    );
    expect(
      hasUnreadProblem([
        { unread: true, severity: "INFO" },
        { unread: true, severity: "WARNING" },
      ]),
    ).toBe(true);
  });

  it("keys an alert by its service and id, as its deep links do", () => {
    expect(getAlertKey({ source: "ssl", id: "7" })).toBe("ssl:7");
  });
});
