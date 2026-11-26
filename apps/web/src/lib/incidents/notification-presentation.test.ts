// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  getNotificationReasonLabel,
  getNotificationStatusBadgeLabel,
  getNotificationStatusBadgeVariant,
  getNotificationStatusLabel,
} from "@/lib/incidents/notification-presentation";

describe("notification presentation", () => {
  it("says a suppressed notification was not sent because of the settings", () => {
    expect(getNotificationStatusLabel("SUPPRESSED")).toBe(
      "Not sent: turned off in notification settings",
    );
    expect(getNotificationStatusBadgeLabel("SUPPRESSED")).toBe("Not sent");
    expect(getNotificationStatusBadgeLabel("FAILED")).toBe("Failed");
    expect(getNotificationStatusBadgeVariant("SUPPRESSED")).toBe("secondary");
  });

  it("reads any other status as words", () => {
    expect(getNotificationStatusLabel("DELIVERED")).toBe("Delivered");
    expect(getNotificationStatusLabel(null)).toBe("Unknown");
  });

  it("names the category a suppressed notification belongs to", () => {
    expect(
      getNotificationReasonLabel({
        status: "SUPPRESSED",
        failureReason: "ORG_PREFERENCE:CERTIFICATE_ACTIVITY",
      }),
    ).toBe("Certificate activity is turned off in notification settings.");
    expect(
      getNotificationReasonLabel({
        status: "SUPPRESSED",
        failureReason: "ORG_PREFERENCE:SOMETHING_NEW",
      }),
    ).toBe("Another category is turned off in notification settings.");
    expect(
      getNotificationReasonLabel({ status: "SUPPRESSED", failureReason: "x" }),
    ).toBe("This notification is turned off in notification settings.");
    expect(
      getNotificationReasonLabel({ status: "SUPPRESSED", failureReason: null }),
    ).toBe("This notification is turned off in notification settings.");
  });

  it("keeps any other reason as the notifier wrote it", () => {
    expect(
      getNotificationReasonLabel({
        status: "FAILED",
        failureReason: "NO_RECIPIENT",
      }),
    ).toBe("NO_RECIPIENT");
    expect(
      getNotificationReasonLabel({ status: "FAILED", failureReason: null }),
    ).toBeNull();
  });
});
