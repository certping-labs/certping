// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { hasAuditTrailFilters } from "@/lib/audit-trail-filters";
import { notificationCategoryLabel } from "@/lib/notification-settings";
import type { AuditTrailDatePreset } from "@/lib/audit-trail-source";
import {
  AUDIT_TRAIL_ALL_VISIBILITIES,
  type AuditTrailFilters,
} from "@/types/audit-trail";

/**
 * The cert-manager audit page's filters as they live in the URL, and the
 * words its codes read in.
 */

/** Customers see this many days back (`certping.audit.customer-visible-days`). */
export const AUDIT_VISIBLE_DAYS = 90;
/** One query covers at most this many days; the platform route refuses more. */
export const AUDIT_MAX_RANGE_DAYS = 90;
/** cert-manager serves at most this many rows a page. */
export const AUDIT_MAX_PAGE_SIZE = 100;

const HOUR_MS = 60 * 60 * 1_000;
const DAY_HOURS = 24;
const DAY_MS = DAY_HOURS * HOUR_MS;

export const AUDIT_DATE_PRESETS: readonly AuditTrailDatePreset[] = [
  { id: "24h", label: "Last 24 hours", hours: DAY_HOURS },
  { id: "7d", label: "Last 7 days", hours: 7 * DAY_HOURS },
  { id: "30d", label: "Last 30 days", hours: 30 * DAY_HOURS },
  {
    id: "90d",
    label: "Last 90 days",
    hours: AUDIT_VISIBLE_DAYS * DAY_HOURS,
    default: true,
  },
];

const CUSTOMER_FILTER_KEYS = [
  "requestId",
  "userId",
  "actorType",
  "category",
  "status",
  "range",
  "from",
  "to",
] as const satisfies readonly (keyof AuditTrailFilters)[];

const PLATFORM_FILTER_KEYS = [
  ...CUSTOMER_FILTER_KEYS,
  "organizationId",
  "visibility",
] as const satisfies readonly (keyof AuditTrailFilters)[];

const filterKeys = (platform: boolean) =>
  platform ? PLATFORM_FILTER_KEYS : CUSTOMER_FILTER_KEYS;

const isPreset = (range: string) =>
  AUDIT_DATE_PRESETS.some((preset) => preset.id === range);

export const readAuditFilters = (
  params: Pick<URLSearchParams, "get">,
  platform: boolean,
): AuditTrailFilters => {
  const filters: AuditTrailFilters = {};
  for (const key of filterKeys(platform)) {
    const value = params.get(key)?.trim();
    if (value) {
      filters[key] = value;
    }
  }
  // A preset wins over days, and an unknown preset is no filter.
  if (filters.range && !isPreset(filters.range)) {
    delete filters.range;
  }
  if (filters.range) {
    delete filters.from;
    delete filters.to;
  }
  return filters;
};

export const writeAuditFilters = (
  filters: AuditTrailFilters,
  platform: boolean,
): string => {
  const params = new URLSearchParams();
  for (const key of filterKeys(platform)) {
    const value = filters[key]?.trim();
    if (value) {
      params.set(key, value);
    }
  }
  return params.toString();
};

export const hasAuditFilters = hasAuditTrailFilters;

export const auditRangeError = (
  filters: AuditTrailFilters,
  platform = false,
): string | undefined => {
  if (!filters.from || !filters.to) {
    return undefined;
  }
  const from = Date.parse(filters.from);
  const to = Date.parse(filters.to);
  if (Number.isNaN(from) || Number.isNaN(to)) {
    return "Choose a valid date range.";
  }
  if (from > to) {
    return "The start date must be before the end date.";
  }
  // Customers' ranges are clamped to their window, which is no longer.
  if (platform && to - from > AUDIT_MAX_RANGE_DAYS * DAY_MS) {
    return `Choose a range of ${AUDIT_MAX_RANGE_DAYS} days or less.`;
  }
  return undefined;
};

/**
 * Where a preset starts, read when the request is made so a refresh stays
 * relative to now.
 */
export const presetStart = (
  range: string | undefined,
  now: number = Date.now(),
): string | undefined => {
  const preset = AUDIT_DATE_PRESETS.find((candidate) => candidate.id === range);
  return preset
    ? new Date(now - preset.hours * HOUR_MS).toISOString()
    : undefined;
};

/** The categories of `AuditCategory`, for rows whose list was not read. */
const CATEGORY_LABELS: Readonly<Record<string, string>> = {
  ACCESS_CONTROL: "Access control",
  AUTHENTICATION: "Sign-in",
  ORGANIZATION: "Organization",
  CERTIFICATES: "Certificates",
  DEPLOYMENTS: "Deployments",
  CREDENTIALS: "Credentials",
  DISCOVERY: "Discovery",
  MONITORING: "Monitoring",
  MACHINE_IDENTITY: "Machine identity",
  INTEGRATIONS: "Integrations",
  SUPPORT: "Support",
  ACCESS: "Sensitive access",
  PLATFORM: "Platform",
};

const LABELS: Readonly<Record<string, string>> = {
  SUCCESS: "Succeeded",
  FAILURE: "Failed",
  PENDING: "Pending",
  USER: "Member",
  SYSTEM: "CertPing (automatic)",
  ANONYMOUS: "Someone",
  API_TOKEN: "API token",
  STAFF: "Platform administrator",
  CUSTOMER: "Customer",
  INTERNAL: "Internal",
  [AUDIT_TRAIL_ALL_VISIBILITIES]: "Customer and internal",
  NOTIFICATION_SETTINGS_CHANGE: "Notification settings changed",
  ...CATEGORY_LABELS,
};

const ACRONYMS = new Set([
  "ACME",
  "API",
  "CA",
  "CSR",
  "DNS",
  "IP",
  "IOT",
  "MFA",
  "PQC",
  "SSO",
  "SSL",
  "TLS",
]);

/** A readable label for a server code: "CERTIFICATE_RENEW" is "Certificate renew". */
export const auditLabel = (code: string): string => {
  const known = LABELS[code];
  if (known) {
    return known;
  }
  const words = code
    .split(/[_.\s]+/)
    .filter(Boolean)
    .map((word) =>
      ACRONYMS.has(word.toUpperCase())
        ? word.toUpperCase()
        : word.toLowerCase(),
    );
  if (words.length === 0) {
    return code;
  }
  const [first, ...rest] = words;
  return [first.charAt(0).toUpperCase() + first.slice(1), ...rest].join(" ");
};

export const auditCategoryLabel = (category: string): string =>
  CATEGORY_LABELS[category] ?? auditLabel(category);

/** "access.certificate_exported" reads "Certificate exported". */
export const auditAccessLabel = (activity: string): string =>
  auditLabel(activity.replace(/^access\./, ""));

/** Change fields whose name and values read better than the stored ones. */
const CHANGE_FIELD_LABELS: Readonly<Record<string, string>> = {
  mutedCategories: "Notifications turned off",
};

/** A change field's name in words; any other field as stored. */
export const auditChangeFieldLabel = (field: string): string =>
  CHANGE_FIELD_LABELS[field] ?? field;

/**
 * A change's recorded value in words: the turned-off notification categories
 * by name ("None" for none); any other value as stored.
 */
export const auditChangeValueLabel = (field: string, value: string): string => {
  if (field !== "mutedCategories") {
    return value;
  }
  const keys = value.split(",").filter(Boolean);
  return keys.length === 0
    ? "None"
    : keys.map(notificationCategoryLabel).join(", ");
};
