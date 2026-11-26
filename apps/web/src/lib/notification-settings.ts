// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import axios from "axios";

import { FEATURE_FLAGS } from "@/lib/feature-flags";

/** Whether a feature is on for the organization. */
export type FeatureCheck = (featureKey: string) => boolean;

/** Text shown only while one of its features is on; a clause with no features is always shown. */
interface Clause {
  text: string;
  features?: readonly string[];
}

const shown = (clauses: readonly Clause[], isEnabled: FeatureCheck) =>
  clauses
    .filter(({ features }) => !features || features.some(isEnabled))
    .map(({ text }) => text);

/** "a", "a or b", "a, b or c". */
export function joinList(items: readonly string[], conjunction: "and" | "or") {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} ${conjunction} ${items[items.length - 1]}`;
}

/** A series of phrases that may contain "and" themselves: "a", "a and b", "a, b, and c". */
function joinSeries(items: readonly string[]) {
  if (items.length <= 2) return items.join(" and ");
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
}

const sentence = (text: string) =>
  `${text.charAt(0).toUpperCase()}${text.slice(1)}.`;

const ISSUANCE = [
  FEATURE_FLAGS.CERTIFICATE_ISSUANCE,
  FEATURE_FLAGS.CERTIFICATE_MANUAL_ISSUANCE,
];
const RENEWAL = [FEATURE_FLAGS.CERTIFICATE_RENEWAL];
const DEPLOYMENT = [FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT];

/**
 * The notification categories an organization admin can turn off, in the
 * order the server serves them (`NotificationCategory`). Each turns off the
 * email and the Slack, Teams, PagerDuty and ServiceNow messages alike. A
 * description names only what the organization's features can send, and is
 * null when they send nothing in the category.
 */
export const NOTIFICATION_CATEGORIES = [
  {
    key: "CERTIFICATE_ACTIVITY",
    label: "Certificate activity",
    describe: (isEnabled: FeatureCheck) => {
      const events = shown(
        [
          { text: "issued", features: ISSUANCE },
          { text: "renewed", features: RENEWAL },
          { text: "deployed", features: DEPLOYMENT },
        ],
        isEnabled,
      );
      return events.length
        ? sentence(`a certificate was ${joinList(events, "or")}`)
        : null;
    },
  },
  // The server serves only these categories.
  {
    key: "REPORTS",
    label: "Reports and digests",
    describe: () =>
      "Scan reports and activity digests. Findings stay in the app.",
  },
] as const;

export type NotificationCategoryKey =
  (typeof NOTIFICATION_CATEGORIES)[number]["key"];

/** The categories the organization's features can send, each with its description. */
export function notificationCategories(isEnabled: FeatureCheck) {
  return NOTIFICATION_CATEGORIES.flatMap(({ key, label, describe }) => {
    const description = describe(isEnabled);
    return description ? [{ key, label, description }] : [];
  });
}

/** What is sent whatever the settings say, for the organization's features. */
export function alwaysSentNotifications(isEnabled: FeatureCheck) {
  const failures = shown(
    [
      { text: "issuance", features: ISSUANCE },
      { text: "renewal", features: RENEWAL },
      { text: "deployment", features: DEPLOYMENT },
    ],
    isEnabled,
  );
  const expiring = ["certificates"];
  const groups = [
    {
      label: "Security and account",
      items: ["password reset and sign-in emails", "revoked certificates"],
    },
    {
      label: "Failures, expiry and action needed",
      items: [
        ...(failures.length ? [`failed ${joinList(failures, "or")}`] : []),
        `expiring ${joinList(expiring, "and")}`,
      ],
    },
    {
      label: "Service changes",
      items: ["features an administrator pauses or resumes"],
    },
  ];
  return groups
    .filter(({ items }) => items.length > 0)
    .map(({ label, items }) => ({
      label,
      description: sentence(joinSeries(items)),
    }));
}

/** Which channels each choice covers: email always, the chat and paging integrations while they are on. */
export function notificationChannels(isEnabled: FeatureCheck): string {
  return isEnabled(FEATURE_FLAGS.INTEGRATIONS)
    ? "Each choice covers email and the Slack, Teams, PagerDuty and ServiceNow integrations."
    : "Each choice covers email.";
}

export const NOTIFICATION_SETTINGS_UNAVAILABLE =
  "Notification settings aren't available. Ask your CertPing administrator.";

const SAVE_FAILED =
  "Notification settings couldn't be saved. Please try again.";

/** The label of a category key; "Another category" for one this app does not know yet. */
export function notificationCategoryLabel(key: string): string {
  return (
    NOTIFICATION_CATEGORIES.find((category) => category.key === key)?.label ??
    "Another category"
  );
}

/** True when the server refused because notification settings are off (423). */
export function isNotificationSettingsUnavailable(error: unknown): boolean {
  return axios.isAxiosError(error) && error.response?.status === 423;
}

/**
 * What to tell an admin whose save failed: the generic line while settings
 * are off, and otherwise a retry, a refused list (400) included.
 */
export function notificationSettingsSaveError(error: unknown): string {
  return isNotificationSettingsUnavailable(error)
    ? NOTIFICATION_SETTINGS_UNAVAILABLE
    : SAVE_FAILED;
}
