// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { AuditRetention } from "@/lib/backend/audit-retention";
import { formatDate, formatDateTime } from "@/lib/utils";

/**
 * Audit retention rules the super-admin card shares with cert-manager
 * (`AuditRetentionService`): the period bounds, how a reason is cleaned and
 * counted, when a save takes effect and which month it keeps from.
 */

/** Used until the API has answered; the API's own bounds win afterwards. */
export const DEFAULT_MIN_MONTHS = 6;
export const DEFAULT_MAX_MONTHS = 36;
export const MAX_REASON_LENGTH = 500;

/**
 * The first confirmation and every shortening wait this long before the
 * retention job may delete (`certping.jobs.audit-retention.grace`).
 */
const GRACE_MS = 24 * 60 * 60 * 1000;
/** The retention job's daily run (`certping.jobs.audit-retention.cron`, 04:30 UTC). */
const RUN_HOUR_UTC = 4;
const RUN_MINUTE_UTC = 30;

export type RetentionChoice = "6" | "12" | "24" | "36" | "custom";

export const RETENTION_CHOICES: readonly {
  value: RetentionChoice;
  label: string;
}[] = [
  { value: "6", label: "6 months" },
  { value: "12", label: "1 year" },
  { value: "24", label: "2 years" },
  { value: "36", label: "3 years" },
  { value: "custom", label: "Custom" },
];

/** The preset a period matches, or "custom". */
export function choiceForMonths(months: number): RetentionChoice {
  const match = RETENTION_CHOICES.find(
    (choice) => choice.value === String(months),
  );
  return match ? match.value : "custom";
}

/** "6 months", "1 year", "2 years", "18 months". */
export function formatRetentionPeriod(months: number): string {
  if (months > 0 && months % 12 === 0) {
    const years = months / 12;
    return years === 1 ? "1 year" : `${years} years`;
  }
  return months === 1 ? "1 month" : `${months} months`;
}

function parseMonth(month: string): { year: number; monthIndex: number } {
  const [year, monthNumber] = month.split("-").map(Number);
  return { year, monthIndex: monthNumber - 1 };
}

/** "2025-10" as "October 2025". */
export function formatMonth(month: string): string {
  const { year, monthIndex } = parseMonth(month);
  return new Date(Date.UTC(year, monthIndex, 1)).toLocaleDateString("en-US", {
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  });
}

/**
 * "2025-10" as its first day in UTC, "Oct 1, 2025 (UTC)": the retention job
 * cuts at UTC month starts, and every earlier entry is deleted.
 */
export function formatMonthStart(month: string): string {
  const { year, monthIndex } = parseMonth(month);
  const day = new Date(Date.UTC(year, monthIndex, 1)).toLocaleDateString(
    "en-US",
    { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" },
  );
  return `${day} (UTC)`;
}

export type MonthsValidation =
  { months: number; error: null } | { months: null; error: string };

/** Mirrors the server: a whole number from `min` to `max` months. */
export function validateMonths(
  raw: string,
  min: number,
  max: number,
): MonthsValidation {
  const value = raw.trim();
  if (value === "") {
    return { months: null, error: "Enter a number of months." };
  }
  if (!/^\d+$/.test(value)) {
    return { months: null, error: "Enter a whole number of months." };
  }
  const months = Number(value);
  if (months < min || months > max) {
    return {
      months: null,
      error: `Audit retention must be between ${min} and ${max} months.`,
    };
  }
  return { months, error: null };
}

/** Control and format characters (bidi overrides, zero-width) and line or paragraph separators. */
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/** The reason as the server stores it: unprintables to spaces, whitespace collapsed, ends trimmed. */
export function cleanReason(raw: string): string {
  return raw.replace(UNPRINTABLE, " ").replace(/\s+/g, " ").trim();
}

/** Characters the server counts (code points of the cleaned reason). */
export function reasonLength(raw: string): number {
  return Array.from(cleanReason(raw)).length;
}

export type ReasonValidation =
  { reason: string; error: null } | { reason: null; error: string };

/** Mirrors the server: 1 to 500 characters once cleaned. */
export function validateReason(raw: string): ReasonValidation {
  const reason = cleanReason(raw);
  if (reason === "") {
    return { reason: null, error: "A reason is required." };
  }
  if (Array.from(reason).length > MAX_REASON_LENGTH) {
    return {
      reason: null,
      error: `The reason must be at most ${MAX_REASON_LENGTH} characters.`,
    };
  }
  return { reason, error: null };
}

/**
 * Fallback for backends without `deletionWouldStartAt`: the first run at
 * least 24 hours from `nowMs` on the default schedule (04:30 UTC daily, 24h
 * grace). Shown as "about", since ops can change both.
 */
export function estimateEffectiveFrom(nowMs: number): Date {
  const earliest = new Date(nowMs + GRACE_MS);
  const run = new Date(
    Date.UTC(
      earliest.getUTCFullYear(),
      earliest.getUTCMonth(),
      earliest.getUTCDate(),
      RUN_HOUR_UTC,
      RUN_MINUTE_UTC,
    ),
  );
  if (run.getTime() < earliest.getTime()) {
    run.setUTCDate(run.getUTCDate() + 1);
  }
  return run;
}

/** The oldest month (`YYYY-MM`) a run at `at` keeps: its UTC month and the `months` before it. */
export function oldestRetainedMonthAt(at: Date, months: number): string {
  const month = new Date(
    Date.UTC(at.getUTCFullYear(), at.getUTCMonth() - months, 1),
  );
  return `${month.getUTCFullYear()}-${String(month.getUTCMonth() + 1).padStart(2, "0")}`;
}

export type RetentionChange =
  "first-confirmation" | "shorten" | "lengthen" | "reconfirm";

/** What saving `months` does: the first confirmation and a shortening start the grace period. */
export function classifyRetentionChange(
  current: Pick<AuditRetention, "confirmed" | "months">,
  months: number,
): RetentionChange {
  if (!current.confirmed) return "first-confirmation";
  if (months < current.months) return "shorten";
  if (months > current.months) return "lengthen";
  return "reconfirm";
}

export interface RetentionSaveCopy {
  change: RetentionChange;
  title: string;
  description: string;
  /** Irreversible effects, shown as a critical callout; empty when nothing new is deleted. */
  consequences: string[];
  caveat: string;
  actionLabel: string;
  destructive: boolean;
}

const NO_RESTORE_CAVEAT =
  "After you confirm, raising retention later won't bring back older history into the audit log.";

export type DeletionHold = "KILL_SWITCH";

const HOLD_CLEARS: Record<DeletionHold, string> = {
  KILL_SWITCH: "automatic deletion resumes",
};

/** What holds deletion now: the server says so, or (older backends) its flags do. */
export function deletionHeldBy(retention: AuditRetention): DeletionHold | null {
  if (retention.deletionHeldBy !== undefined) return retention.deletionHeldBy;
  if (!retention.automaticDeletionEnabled) return "KILL_SWITCH";
  return null;
}

/**
 * When a grace-starting confirmation would first delete: the server's
 * `deletionWouldStartAt` (null while the kill switch holds the job), or, from
 * an older backend without it, an estimate from the default schedule.
 */
export function deletionStart(
  retention: AuditRetention,
  nowMs: number,
): { at: Date | null; estimated: boolean } {
  if (retention.deletionWouldStartAt !== undefined) {
    return {
      at: retention.deletionWouldStartAt
        ? new Date(retention.deletionWouldStartAt)
        : null,
      estimated: false,
    };
  }
  return { at: estimateEffectiveFrom(nowMs), estimated: true };
}

/** What a grace-starting save (first confirmation, shortening) deletes, and when. */
function deletionConsequences(
  retention: AuditRetention,
  months: number,
  nowMs: number,
): string[] {
  const period = formatRetentionPeriod(months);
  const start = deletionStart(retention, nowMs);
  const hold = deletionHeldBy(retention);
  const date = start.at
    ? `${start.estimated ? "about " : ""}${formatDateTime(start.at.toISOString())}`
    : null;
  const notBefore = date ? `, no earlier than ${date}` : "";
  const firstRun = hold
    ? `at the first deletion run after ${HOLD_CLEARS[hold]}${notBefore}`
    : date
      ? `no earlier than ${date}`
      : "at the next deletion run";

  if (!start.at) {
    return [
      `Entries older than ${period} will be permanently deleted ${firstRun}.`,
      "Deleted entries can't be recovered.",
    ];
  }
  const cutoff = oldestRetainedMonthAt(start.at, months);
  const storesOlderEntries =
    retention.oldestStoredMonth !== null &&
    retention.oldestStoredMonth < cutoff;
  if (!storesOlderEntries) {
    return [
      `Nothing is deleted now; entries are deleted as they turn ${period} old, starting ${firstRun}.`,
      "Deleted entries can't be recovered.",
    ];
  }
  return [
    `Entries before ${formatMonth(cutoff)} will be permanently deleted ${firstRun}.`,
    "Deleted entries can't be recovered.",
  ];
}

/** The confirmation dialog's copy for saving `months`, as of `nowMs`. */
export function describeRetentionSave(
  current: AuditRetention,
  months: number,
  nowMs: number,
): RetentionSaveCopy {
  const change = classifyRetentionChange(current, months);
  const period = formatRetentionPeriod(months);
  const previous = formatRetentionPeriod(current.months);

  if (change === "first-confirmation") {
    return {
      change,
      title: `Confirm ${period} of audit history?`,
      description: `Confirming turns on automatic deletion of entries older than ${period}. Deletion waits for a grace period of at least a day; until then you can still change the period.`,
      consequences: deletionConsequences(current, months, nowMs),
      caveat: NO_RESTORE_CAVEAT,
      actionLabel: `Confirm ${period}`,
      destructive: true,
    };
  }

  if (change === "shorten") {
    return {
      change,
      title: `Shorten audit retention to ${period}?`,
      description: `Retention goes from ${previous} to ${period}. A grace period of at least a day starts now; until the deletion run you can restore ${previous}.`,
      consequences: deletionConsequences(current, months, nowMs),
      caveat: NO_RESTORE_CAVEAT,
      actionLabel: `Shorten to ${period}`,
      destructive: true,
    };
  }

  if (change === "lengthen") {
    return {
      change,
      title: `Keep audit history for ${period}?`,
      description: `Retention goes from ${previous} to ${period}. This change deletes nothing, and the next deletion run keeps more history.`,
      consequences: [],
      caveat:
        "Entries already deleted can't be brought back, and older history isn't copied back into the audit log.",
      actionLabel: `Save ${period}`,
      destructive: false,
    };
  }

  return {
    change,
    title: `Confirm ${period} again?`,
    description:
      "The period stays the same. Saving records your confirmation and reason; it doesn't change when entries are deleted.",
    consequences: [],
    caveat: NO_RESTORE_CAVEAT,
    actionLabel: "Confirm",
    destructive: false,
  };
}

export type RetentionStatusTone = "warning" | "info" | "success";

export interface RetentionStatus {
  kind: "unconfirmed" | "paused" | "active";
  tone: RetentionStatusTone;
  title: string;
  details: string[];
}

/** The card's headline: what the retention job does with this setting today. */
export function retentionStatus(retention: AuditRetention): RetentionStatus {
  const confirmedOn = `Confirmed on ${formatDate(retention.confirmedAt)}.`;

  if (!retention.confirmed) {
    return {
      kind: "unconfirmed",
      tone: "warning",
      title: "Automatic deletion is waiting for confirmation",
      details: [
        "Nothing is deleted until a super admin confirms a period. Saving any period confirms it.",
        ...(retention.automaticDeletionEnabled
          ? []
          : ["Automatic deletion is also paused."]),
      ],
    };
  }
  if (!retention.automaticDeletionEnabled) {
    return {
      kind: "paused",
      tone: "warning",
      title: "Automatic deletion is paused",
      details: [
        "The retention job is held by AUDIT_RETENTION_PURGE or its environment switch, so nothing is deleted.",
        confirmedOn,
      ],
    };
  }
  const cutoff = retention.oldestRetainedMonth
    ? `Entries older than ${formatMonthStart(retention.oldestRetainedMonth)} are deleted daily`
    : "Entries past the period are deleted daily";
  return {
    kind: "active",
    tone: "success",
    title: `Confirmed on ${formatDate(retention.confirmedAt)} · ${cutoff}`,
    details: retention.effectiveFrom
      ? [`Next deletion run: ${formatDateTime(retention.effectiveFrom)}.`]
      : [],
  };
}
