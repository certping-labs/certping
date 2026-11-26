// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type {
  AuditTrailAccessSource,
  AuditTrailDetailField,
  AuditTrailNotice,
  AuditTrailSource,
  AuditTrailViews,
} from "@/lib/audit-trail-source";
import {
  canViewOrganizationAudit,
  canViewPlatformAudit,
  hasOrganizationContext,
} from "@/lib/authz";
import {
  exportAuditAccessLog,
  exportAuditLogs,
  getAuditAccessActivities,
  getAuditAccessLog,
  getAuditLogs,
  getAuditOptions,
} from "@/lib/backend/cert-manager-audit";
import {
  AUDIT_DATE_PRESETS,
  AUDIT_VISIBLE_DAYS,
  auditAccessLabel,
  auditCategoryLabel,
  auditLabel,
  auditRangeError,
  hasAuditFilters,
  readAuditFilters,
  writeAuditFilters,
} from "@/lib/cert-manager-audit-filters";
import { DOCS_URL } from "@/lib/support-links";
import { describeUserAgent } from "@/lib/user-agent";
import type { AuditTrailEntry } from "@/types/audit-trail";

// Under the old page's keys, so `invalidateAuditQueries` still refreshes them.
export const CERT_MANAGER_AUDIT_QUERY_KEY = ["audit-logs"] as const;
export const CERT_MANAGER_AUDIT_OPTIONS_QUERY_KEY = [
  "audit-log-options",
] as const;
export const CERT_MANAGER_AUDIT_ACCESS_QUERY_KEY = [
  "audit-logs",
  "access",
] as const;

export const AUDIT_LOGS_PATH = "/settings/audit-logs";
export const AUDIT_ACCESS_VIEW = "access";
const ACTIVITY_VIEW = "activity";
/** Both logs refuse an export with one message, so one toast holds it. */
const EXPORT_ERROR_TOAST_ID = "audit-log-export-error";

const AUDIT_VIEWS: AuditTrailViews = {
  label: "Audit log views",
  items: [
    { id: ACTIVITY_VIEW, label: "Activity", href: AUDIT_LOGS_PATH },
    {
      id: AUDIT_ACCESS_VIEW,
      label: "Access",
      href: `${AUDIT_LOGS_PATH}?view=${AUDIT_ACCESS_VIEW}`,
    },
  ],
};

const LIST_COPY = {
  loading: "Loading the audit log",
  loadError: "Couldn't load the audit log",
  totalCapped: (count: string, rows: string) => `${count}+ ${rows}`,
  datePlaceholder: "Last 90 days",
  unavailable: {
    title: "The audit log isn't available here",
    description: "It can't be read here yet. Try again later.",
  },
} as const;

/**
 * Older entries stay in the installation's own database; the docs say how an
 * administrator reads them.
 */
const windowNotice = (): AuditTrailNotice => ({
  message: `Showing the last ${AUDIT_VISIBLE_DAYS} days`,
  action: {
    prompt: "Need older logs?",
    label: "Read the docs",
    href: DOCS_URL,
  },
});

/** "Failed: You don't have permission to do this." */
export const auditFailureLine = (entry: AuditTrailEntry): string | undefined =>
  entry.status === "FAILURE"
    ? `Failed: ${entry.reason ?? "Something went wrong."}`
    : undefined;

/**
 * Who acted beyond their name: the member an automatic row acted for (and,
 * on the platform view, the job), or a member's email when their name shows.
 */
export const auditActorDetail = (
  entry: AuditTrailEntry,
): string | undefined => {
  // Only the platform route names the job behind a system row.
  const job = entry.actor?.startsWith("system:")
    ? entry.actor.slice("system:".length)
    : undefined;
  const requestedBy = entry.requestedByName
    ? `requested by ${entry.requestedByName}`
    : undefined;
  if (job || requestedBy) {
    return [job, requestedBy].filter(Boolean).join(" · ");
  }
  if (
    entry.actorType === "USER" &&
    entry.userEmail &&
    entry.userEmail !== entry.actorName
  ) {
    return entry.userEmail;
  }
  return undefined;
};

/** How cert-manager names a sign-in method (`attributes.method` of auth.* rows). */
const SIGN_IN_METHODS: Readonly<Record<string, string>> = {
  PASSWORD: "Password",
  OIDC: "Single sign-on (OIDC)",
  GOOGLE: "Google",
  MICROSOFT: "Microsoft",
  GITHUB: "GitHub",
  LINKEDIN: "LinkedIn",
};

/**
 * The resource a row names, if it names one. A sign-in or a sign-out is about
 * no named thing, so it has no resource field rather than "Auth: None".
 */
export const auditResourceField = (
  entry: AuditTrailEntry,
): AuditTrailDetailField | undefined => {
  const value = entry.resourceName ?? entry.resourceRef;
  if (!value) {
    return undefined;
  }
  const reference =
    entry.resourceRef && entry.resourceRef !== value
      ? entry.resourceRef
      : undefined;
  return {
    label: "Resource",
    value,
    detail: [auditLabel(entry.resource), reference].filter(Boolean).join(" · "),
  };
};

/**
 * How a member signed in, on sign-in rows that record it. The server writes
 * the method before a session exists, so it is in the row's attributes;
 * absent or NONE, there is no field.
 */
export const auditDetailFields = (
  entry: AuditTrailEntry,
): readonly AuditTrailDetailField[] => {
  const method = entry.attributes.method?.trim().toUpperCase();
  if (!entry.event?.startsWith("auth.") || !method || method === "NONE") {
    return [];
  }
  return [
    {
      label: "Sign-in method",
      value: SIGN_IN_METHODS[method] ?? auditLabel(method),
    },
  ];
};

/** Who searched, viewed and exported the organization's sensitive data. */
export const certManagerAccessSource: AuditTrailAccessSource = {
  queryKey: CERT_MANAGER_AUDIT_ACCESS_QUERY_KEY,
  list: ({ filters, size, cursor }) =>
    getAuditAccessLog({ filters, size, cursor }),
  activities: getAuditAccessActivities,
  export: exportAuditAccessLog,
  exportErrorToastId: EXPORT_ERROR_TOAST_ID,
  canView: canViewOrganizationAudit,
  filters: {
    read: (params) => {
      const filters: Record<string, string> = {};
      for (const key of [
        "activity",
        "userId",
        "resourceName",
        "status",
        "from",
        "to",
      ] as const) {
        const value = params.get(key)?.trim();
        if (value) {
          filters[key] = value;
        }
      }
      return filters;
    },
    write: (filters) => {
      const params = new URLSearchParams({ view: AUDIT_ACCESS_VIEW });
      for (const [key, value] of Object.entries(filters)) {
        if (typeof value === "string" && value.trim()) {
          params.set(key, value.trim());
        }
      }
      return params.toString();
    },
    has: (filters) =>
      Object.values(filters).some((value) => Boolean(value?.trim())),
    rangeError: (filters) => auditRangeError(filters),
  },
  results: ["SUCCESS", "FAILURE"],
  codeLabel: auditLabel,
  activityLabel: auditAccessLabel,
  copy: {
    ...LIST_COPY,
    title: "Audit logs",
    breadcrumbs: [],
    subtitle:
      "Who viewed, downloaded and exported sensitive data, such as private keys and this log.",
    noPermission: "You don't have permission to view the audit log.",
    refresh: "Refresh access log",
    empty: {
      title: "No sensitive access yet",
      description:
        "Views, downloads and exports of sensitive data appear here as they happen.",
      filteredTitle: "No access matches these filters",
    },
    endOfList: "No more entries.",
    total: { one: "entry", other: "entries" },
    exportNoun: "entry",
    target: "Resource or search",
    targetPlaceholder: "Name",
    unavailable: {
      title: "The Access log isn't available yet",
      description: "It arrives with the next CertPing update.",
    },
  },
  views: AUDIT_VIEWS,
  viewId: AUDIT_ACCESS_VIEW,
  optional: true,
};

/**
 * cert-manager's audit log: what the organization's members and CertPing
 * did, and why anything failed; or, for a super admin outside any
 * organization, every organization's.
 */
export const certManagerAuditSource: AuditTrailSource = {
  queryKeys: {
    list: CERT_MANAGER_AUDIT_QUERY_KEY,
    options: CERT_MANAGER_AUDIT_OPTIONS_QUERY_KEY,
  },
  list: getAuditLogs,
  options: getAuditOptions,
  export: exportAuditLogs,
  exportsPlatform: true,
  exportErrorToastId: EXPORT_ERROR_TOAST_ID,
  canView: (user, isSuperAdmin, platform) =>
    platform
      ? canViewPlatformAudit(user, isSuperAdmin)
      : canViewOrganizationAudit(user),
  // The customer lists read the session's organization.
  canLoadOptions: (user, platform) => platform || hasOrganizationContext(user),
  filters: {
    read: readAuditFilters,
    write: writeAuditFilters,
    has: hasAuditFilters,
    rangeError: auditRangeError,
  },
  codes: {
    results: ["SUCCESS", "FAILURE"],
    actorTypes: ["USER", "SYSTEM", "ANONYMOUS"],
  },
  codeLabel: auditLabel,
  resourceLabel: (entry) => auditLabel(entry.resource),
  resourceField: auditResourceField,
  detailFields: auditDetailFields,
  failureLine: auditFailureLine,
  actorDetail: auditActorDetail,
  formatUserAgent: describeUserAgent,
  categoryLabel: auditCategoryLabel,
  separateReferences: true,
  filterFields: {
    customer: ["requestId", "member", "category", "result", "date"],
    platform: [
      "requestId",
      "organization",
      "category",
      "result",
      "actorType",
      "visibility",
      "date",
    ],
  },
  columns: {
    customer: ["event", "actor", "result", "reference", "when"],
    platform: ["event", "actor", "organization", "result", "reference", "when"],
  },
  datePresets: AUDIT_DATE_PRESETS,
  notice: ({ platform }) => (platform ? undefined : windowNotice()),
  copy: {
    ...LIST_COPY,
    customer: {
      title: "Audit logs",
      breadcrumbs: [],
      subtitle:
        "What your team and CertPing did in your organization, and why anything failed.",
    },
    platform: {
      title: "Audit logs",
      breadcrumbs: [],
      subtitle: "Every organization's audit log.",
      info: [
        "Pick an organization to read its log. Reading or exporting it is recorded in that organization's log as Platform administrator.",
      ],
    },
    noPermission: "You don't have permission to view the audit log.",
    refresh: "Refresh audit log",
    empty: {
      title: "No activity yet",
      description:
        "Sign-ins, member and role changes, certificates, deployments and settings changes appear here as they happen.",
      filteredTitle: "No events match these filters",
    },
    endOfList: "No more events.",
    total: { one: "event", other: "events" },
    exportNoun: "event",
    resource: "Resource",
    resourceFilter: { label: "Resource name", placeholder: "Name" },
    cappedHint: (count) =>
      `Showing the first ${count} matching events. Narrow the filters or date range to see older ones.`,
  },
  views: AUDIT_VIEWS,
  viewId: ACTIVITY_VIEW,
  access: certManagerAccessSource,
};
