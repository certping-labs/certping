// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  choiceForMonths,
  classifyRetentionChange,
  cleanReason,
  deletionHeldBy,
  deletionStart,
  describeRetentionSave,
  estimateEffectiveFrom,
  formatMonth,
  formatMonthStart,
  formatRetentionPeriod,
  oldestRetainedMonthAt,
  reasonLength,
  retentionStatus,
  validateMonths,
  validateReason,
} from "@/lib/audit-retention";
import { formatDate, formatDateTime } from "@/lib/utils";
import {
  auditRetentionFixture,
  unconfirmedAuditRetentionFixture,
} from "@/test/fixtures/audit-retention";

const NOW = Date.parse("2026-01-01T00:00:00Z");

describe("periods", () => {
  it.each([
    [6, "6 months"],
    [12, "1 year"],
    [18, "18 months"],
    [24, "2 years"],
    [36, "3 years"],
    [1, "1 month"],
  ])("formats %i months as %s", (months, label) => {
    expect(formatRetentionPeriod(months)).toBe(label);
  });

  it("maps presets to their choice and anything else to custom", () => {
    expect(choiceForMonths(6)).toBe("6");
    expect(choiceForMonths(36)).toBe("36");
    expect(choiceForMonths(18)).toBe("custom");
  });

  it("formats YYYY-MM months", () => {
    expect(formatMonth("2025-10")).toBe("October 2025");
    expect(formatMonthStart("2025-10")).toBe("Oct 1, 2025 (UTC)");
  });
});

describe("validateMonths mirrors the server's 6 to 36", () => {
  it.each(["6", "36", " 12 "])("accepts %s", (raw) => {
    expect(validateMonths(raw, 6, 36).error).toBeNull();
  });

  it.each(["5", "37", "0"])("refuses %s with the bounds", (raw) => {
    expect(validateMonths(raw, 6, 36)).toEqual({
      months: null,
      error: "Audit retention must be between 6 and 36 months.",
    });
  });

  it("refuses empty and fractional values", () => {
    expect(validateMonths("", 6, 36).error).toBe("Enter a number of months.");
    expect(validateMonths("6.5", 6, 36).error).toBe(
      "Enter a whole number of months.",
    );
    expect(validateMonths("-7", 6, 36).error).toBe(
      "Enter a whole number of months.",
    );
  });

  it("uses the bounds it is given", () => {
    expect(validateMonths("8", 9, 24).error).toBe(
      "Audit retention must be between 9 and 24 months.",
    );
  });
});

describe("reasons are cleaned and counted like the server", () => {
  it("turns line breaks and invisible characters into single spaces", () => {
    expect(cleanReason("  Contract\n\nrenewal‮​terms  ")).toBe(
      "Contract renewal terms",
    );
  });

  it("requires something once cleaned", () => {
    expect(validateReason(" \n​ ").error).toBe("A reason is required.");
  });

  it("counts code points, so 500 emoji fit and 501 do not", () => {
    expect(reasonLength("😀".repeat(500))).toBe(500);
    expect(validateReason("😀".repeat(500)).error).toBeNull();
    expect(validateReason("a".repeat(501)).error).toBe(
      "The reason must be at most 500 characters.",
    );
  });

  it("returns the cleaned reason", () => {
    expect(validateReason(" Audit\tpolicy ")).toEqual({
      reason: "Audit policy",
      error: null,
    });
  });
});

describe("when a grace-starting save takes effect", () => {
  it("is the first 04:30 UTC run at least 24 hours away", () => {
    expect(estimateEffectiveFrom(NOW).toISOString()).toBe(
      "2026-01-02T04:30:00.000Z",
    );
    // Saved at 04:29 UTC: not the run a minute later, nor tomorrow's 04:30 minus a minute.
    expect(
      estimateEffectiveFrom(Date.parse("2026-01-01T04:29:00Z")).toISOString(),
    ).toBe("2026-01-02T04:30:00.000Z");
    expect(
      estimateEffectiveFrom(Date.parse("2026-01-01T04:31:00Z")).toISOString(),
    ).toBe("2026-01-03T04:30:00.000Z");
  });

  it("keeps the run's UTC month and the months before it", () => {
    expect(oldestRetainedMonthAt(new Date("2026-10-10T04:30:00Z"), 12)).toBe(
      "2025-10",
    );
    expect(oldestRetainedMonthAt(new Date("2026-01-02T04:30:00Z"), 6)).toBe(
      "2025-07",
    );
    expect(oldestRetainedMonthAt(new Date("2026-01-02T04:30:00Z"), 36)).toBe(
      "2023-01",
    );
  });
});

describe("classifyRetentionChange", () => {
  it("treats any save before the first confirmation as the first confirmation", () => {
    expect(classifyRetentionChange({ confirmed: false, months: 12 }, 36)).toBe(
      "first-confirmation",
    );
  });

  it("tells shorten, lengthen and reconfirm apart once confirmed", () => {
    const current = { confirmed: true, months: 12 };
    expect(classifyRetentionChange(current, 6)).toBe("shorten");
    expect(classifyRetentionChange(current, 24)).toBe("lengthen");
    expect(classifyRetentionChange(current, 12)).toBe("reconfirm");
  });
});

describe("describeRetentionSave", () => {
  const SERVER_START = "2026-01-03T04:30:00Z";
  const serverStart = formatDateTime(SERVER_START);
  const estimate = `about ${formatDateTime("2026-01-02T04:30:00.000Z")}`;
  const CAVEAT =
    "After you confirm, raising retention later won't bring back older history into the audit log.";

  it("uses the server's deletionWouldStartAt, never an estimate", () => {
    const copy = describeRetentionSave(
      auditRetentionFixture({
        months: 24,
        deletionWouldStartAt: SERVER_START,
        deletionHeldBy: null,
      }),
      6,
      NOW,
    );
    expect(copy).toMatchObject({
      change: "shorten",
      title: "Shorten audit retention to 6 months?",
      actionLabel: "Shorten to 6 months",
      destructive: true,
      caveat: CAVEAT,
    });
    expect(copy.description).toContain("from 2 years to 6 months");
    expect(copy.consequences).toEqual([
      `Entries before July 2025 will be permanently deleted no earlier than ${serverStart}.`,
      "Deleted entries can't be recovered.",
    ]);
  });

  it("falls back to an estimate labelled 'about' for an older backend", () => {
    const copy = describeRetentionSave(
      unconfirmedAuditRetentionFixture(),
      12,
      NOW,
    );
    expect(copy).toMatchObject({
      change: "first-confirmation",
      title: "Confirm 1 year of audit history?",
      destructive: true,
      actionLabel: "Confirm 1 year",
      caveat: CAVEAT,
    });
    expect(copy.consequences[0]).toBe(
      `Entries before January 2025 will be permanently deleted no earlier than ${estimate}.`,
    );
  });

  it("derives the hold from an older backend's flags", () => {
    expect(
      describeRetentionSave(
        auditRetentionFixture({ months: 24, automaticDeletionEnabled: false }),
        6,
        NOW,
      ).consequences[0],
    ).toBe(
      `Entries before July 2025 will be permanently deleted at the first deletion run after automatic deletion resumes, no earlier than ${estimate}.`,
    );
  });

  it("gives no date while the kill switch holds the job", () => {
    const copy = describeRetentionSave(
      auditRetentionFixture({
        months: 24,
        automaticDeletionEnabled: false,
        deletionWouldStartAt: null,
        deletionHeldBy: "KILL_SWITCH",
      }),
      6,
      NOW,
    );
    expect(copy.consequences[0]).toBe(
      "Entries older than 6 months will be permanently deleted at the first deletion run after automatic deletion resumes.",
    );
  });

  it("copes with a server that has no date and no hold", () => {
    const copy = describeRetentionSave(
      auditRetentionFixture({
        months: 24,
        deletionWouldStartAt: null,
        deletionHeldBy: null,
      }),
      6,
      NOW,
    );
    expect(copy.consequences[0]).toBe(
      "Entries older than 6 months will be permanently deleted at the next deletion run.",
    );
  });

  it.each([["2025-01"], ["2025-06"], [null]])(
    "says nothing is deleted now when the oldest stored month is %s",
    (oldestStoredMonth) => {
      const copy = describeRetentionSave(
        unconfirmedAuditRetentionFixture({
          oldestStoredMonth,
          deletionWouldStartAt: SERVER_START,
          deletionHeldBy: null,
        }),
        12,
        NOW,
      );
      expect(copy.consequences[0]).toBe(
        `Nothing is deleted now; entries are deleted as they turn 1 year old, starting no earlier than ${serverStart}.`,
      );
      expect(copy.consequences.join(" ")).not.toContain("Entries before");
    },
  );

  it("deletes nothing when lengthening", () => {
    const copy = describeRetentionSave(auditRetentionFixture(), 36, NOW);
    expect(copy).toMatchObject({
      change: "lengthen",
      title: "Keep audit history for 3 years?",
      consequences: [],
      destructive: false,
      actionLabel: "Save 3 years",
    });
    expect(copy.caveat).toContain("can't be brought back");
  });

  it("only records a confirmation when the period is unchanged", () => {
    const copy = describeRetentionSave(auditRetentionFixture(), 12, NOW);
    expect(copy).toMatchObject({
      change: "reconfirm",
      title: "Confirm 1 year again?",
      consequences: [],
      destructive: false,
      actionLabel: "Confirm",
    });
  });
});

describe("deletion hold and start", () => {
  it("prefers the server's answer, including null", () => {
    expect(
      deletionHeldBy(
        auditRetentionFixture({
          automaticDeletionEnabled: false,
          deletionHeldBy: null,
        }),
      ),
    ).toBeNull();
    expect(deletionHeldBy(auditRetentionFixture())).toBeNull();
    expect(
      deletionStart(auditRetentionFixture({ deletionWouldStartAt: null }), NOW),
    ).toEqual({ at: null, estimated: false });
    expect(deletionStart(auditRetentionFixture(), NOW)).toEqual({
      at: new Date("2026-01-02T04:30:00.000Z"),
      estimated: true,
    });
  });
});

describe("retentionStatus", () => {
  it("waits for confirmation first, noting other holds", () => {
    const status = retentionStatus(
      unconfirmedAuditRetentionFixture({ automaticDeletionEnabled: false }),
    );
    expect(status.kind).toBe("unconfirmed");
    expect(status.title).toBe("Automatic deletion is waiting for confirmation");
    expect(status.details).toEqual([
      "Nothing is deleted until a super admin confirms a period. Saving any period confirms it.",
      "Automatic deletion is also paused.",
    ]);
  });

  it("reports a paused job once confirmed (kill switch or environment)", () => {
    const status = retentionStatus(
      auditRetentionFixture({ automaticDeletionEnabled: false }),
    );
    expect(status).toMatchObject({
      kind: "paused",
      tone: "warning",
      title: "Automatic deletion is paused",
    });
    expect(status.details).toContain(
      `Confirmed on ${formatDate("2025-12-20T12:00:00Z")}.`,
    );
  });

  it("states the cutoff once deletion runs", () => {
    const status = retentionStatus(auditRetentionFixture());
    expect(status).toMatchObject({
      kind: "active",
      tone: "success",
      title: `Confirmed on ${formatDate("2025-12-20T12:00:00Z")} · Entries older than Jan 1, 2025 (UTC) are deleted daily`,
    });
    expect(status.details).toEqual([
      `Next deletion run: ${formatDateTime("2026-01-02T04:30:00Z")}.`,
    ]);
  });

  it("copes with a running setting that has no months or run yet", () => {
    const status = retentionStatus(
      auditRetentionFixture({ oldestRetainedMonth: null, effectiveFrom: null }),
    );
    expect(status.title).toContain("Entries past the period are deleted daily");
    expect(status.details).toEqual([]);
  });
});
