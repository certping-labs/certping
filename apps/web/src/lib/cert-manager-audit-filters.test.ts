// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  auditAccessLabel,
  auditCategoryLabel,
  auditChangeFieldLabel,
  auditChangeValueLabel,
  auditLabel,
  auditRangeError,
  presetStart,
  readAuditFilters,
  writeAuditFilters,
} from "@/lib/cert-manager-audit-filters";

describe("cert-manager audit filters", () => {
  it("reads the customer's filters from the URL, trimmed", () => {
    const params = new URLSearchParams(
      "userId=42&category=CREDENTIALS&status=FAILURE&requestId=%20req-1%20&organizationId=9&visibility=ALL&page=3",
    );

    expect(readAuditFilters(params, false)).toEqual({
      userId: "42",
      category: "CREDENTIALS",
      status: "FAILURE",
      requestId: "req-1",
    });
    expect(readAuditFilters(params, true)).toMatchObject({
      organizationId: "9",
      visibility: "ALL",
    });
  });

  it("lets a known preset win over days, and drops an unknown one", () => {
    expect(
      readAuditFilters(
        new URLSearchParams("range=7d&from=2026-01-01&to=2026-01-02"),
        false,
      ),
    ).toEqual({ range: "7d" });
    expect(
      readAuditFilters(new URLSearchParams("range=5y&from=2026-01-01"), false),
    ).toEqual({ from: "2026-01-01" });
  });

  it("writes only the view's keys, and nothing for no filters", () => {
    expect(
      writeAuditFilters({ actorType: "SYSTEM", organizationId: "9" }, false),
    ).toBe("actorType=SYSTEM");
    expect(writeAuditFilters({ organizationId: "9" }, true)).toBe(
      "organizationId=9",
    );
    expect(writeAuditFilters({}, false)).toBe("");
  });

  it("refuses a reversed range, and a long one on the platform view", () => {
    const long = {
      from: "2026-01-01T00:00:00Z",
      to: "2026-06-01T00:00:00Z",
    };
    expect(
      auditRangeError({
        from: "2026-02-01T00:00:00Z",
        to: "2026-01-01T00:00:00Z",
      }),
    ).toBe("The start date must be before the end date.");
    expect(auditRangeError({ from: "x", to: "y" })).toBe(
      "Choose a valid date range.",
    );
    // A customer's range is clamped to the window, so it is never too long.
    expect(auditRangeError(long)).toBeUndefined();
    expect(auditRangeError(long, true)).toBe(
      "Choose a range of 90 days or less.",
    );
    expect(auditRangeError({ from: long.from })).toBeUndefined();
  });

  it("starts a preset its hours before now", () => {
    const now = Date.parse("2026-10-10T00:00:00.000Z");
    expect(presetStart("30d", now)).toBe("2026-09-10T00:00:00.000Z");
    expect(presetStart(undefined, now)).toBeUndefined();
  });

  it("labels codes in words", () => {
    expect(auditLabel("FAILURE")).toBe("Failed");
    expect(auditLabel("SYSTEM")).toBe("CertPing (automatic)");
    expect(auditLabel("SSO_CONFIG_UPDATE")).toBe("SSO config update");
    expect(auditLabel("")).toBe("");
    expect(auditCategoryLabel("AUTHENTICATION")).toBe("Sign-in");
    expect(auditCategoryLabel("NEW_THING")).toBe("New thing");
    expect(auditAccessLabel("access.private_key_downloaded")).toBe(
      "Private key downloaded",
    );
  });

  it("reads a notification settings change in words", () => {
    expect(auditLabel("NOTIFICATION_SETTINGS_CHANGE")).toBe(
      "Notification settings changed",
    );
    expect(auditLabel("notification_settings.changed")).toBe(
      "Notification settings changed",
    );
    expect(auditChangeFieldLabel("mutedCategories")).toBe(
      "Notifications turned off",
    );
    expect(
      auditChangeValueLabel("mutedCategories", "CERTIFICATE_ACTIVITY,REPORTS"),
    ).toBe("Certificate activity, Reports and digests");
    expect(auditChangeValueLabel("mutedCategories", "")).toBe("None");
    expect(auditChangeFieldLabel("retentionDays")).toBe("retentionDays");
    expect(auditChangeValueLabel("retentionDays", "14")).toBe("14");
  });
});
