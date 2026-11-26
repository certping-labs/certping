// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { SsoUser } from "@/types/auth";
import type {
  AuditTrailAccessFilters,
  AuditTrailAccessPage,
  AuditTrailChoice,
  AuditTrailEntry,
  AuditTrailExport,
  AuditTrailExportFormat,
  AuditTrailFilters,
  AuditTrailPage,
} from "@/types/audit-trail";

/**
 * What an audit trail panel needs from the service that records the trail:
 * how to read it, who may, and the words it is shown in. The panels in
 * `components/audit-trail` hold no knowledge of any one service.
 */

type User = SsoUser | null | undefined;

/** The lists a filter offers, each read from the source on demand. */
export type AuditTrailOptionKind =
  "actions" | "resources" | "categories" | "members" | "organizations";

/** What an option list depends on beyond its kind and view. */
export interface AuditTrailOptionScope {
  organizationId?: string;
}

/** A code (labelled by `codeLabel`), or a value with its own label. */
export type AuditTrailOption = string | AuditTrailChoice;

/**
 * The filters a source's bar shows, in order. Without `filterFields` a panel
 * shows the classic bar (name, action, resource, result, actor, dates).
 */
export type AuditTrailFilterField =
  | "requestId"
  | "member"
  | "category"
  | "result"
  | "actorType"
  | "organization"
  | "visibility"
  | "date";

/** The columns a source's table shows, in order. */
export type AuditTrailColumnId =
  | "time"
  | "actor"
  | "organization"
  | "action"
  | "resource"
  | "result"
  | "details"
  /** The summary sentence, why it failed, and its badges. */
  | "event"
  /** The request id, with a copy button. */
  | "reference"
  /** How long ago, with the exact time beneath. */
  | "when";

/** A date preset: "7d" reads "Last 7 days" and starts `hours` ago. */
export interface AuditTrailDatePreset {
  id: string;
  label: string;
  hours: number;
  /** What no date filter reads as (the whole window): choosing it clears. */
  default?: boolean;
}

/** A line around a panel's content, e.g. how far back the log reaches. */
export interface AuditTrailNotice {
  message: string;
  action?: {
    /** Words before the link, e.g. "Need older logs?". */
    prompt?: string;
    label: string;
    /** An in-app path, a mailto: link, or an https URL (opens in a new tab). */
    href: string;
  };
}

export interface AuditTrailNoticeContext {
  user: User;
  platform: boolean;
  /** The first page read, once it has arrived. */
  page?: AuditTrailPage;
}

export interface AuditTrailListQuery {
  filters: AuditTrailFilters;
  /** Super admins read every organization's events, internal ones included. */
  platform: boolean;
  size: number;
  cursor?: string;
}

export interface AuditTrailAccessListQuery {
  filters: AuditTrailAccessFilters;
  size: number;
  cursor?: string;
}

/** The logs of one subject, each a page of its own, linked as tabs. */
export interface AuditTrailViews {
  /** The tabs' accessible name, e.g. "Audit log views". */
  label: string;
  items: readonly { id: string; label: string; href: string }[];
}

export interface AuditTrailHeaderCopy {
  title: string;
  breadcrumbs: readonly { label: string; href: string }[];
  subtitle: string;
  /** What the page is for, behind the header's info icon. */
  info?: readonly string[];
}

/** What a log holds when it holds nothing. */
export interface AuditTrailEmptyCopy {
  title: string;
  description: string;
  filteredTitle: string;
}

/** The words a panel shares with its states, table and export menu. */
export interface AuditTrailListCopy {
  noPermission: string;
  /** The refresh button's accessible name, e.g. "Refresh events". */
  refresh: string;
  /** The loading state's accessible name. */
  loading: string;
  /** The error state's title. */
  loadError: string;
  empty: AuditTrailEmptyCopy;
  /** The table's text past the last row. */
  endOfList: string;
  /** A row as the total counts it: "event" and "events". */
  total: { one: string; other: string };
  /**
   * A capped total, a lower bound: given "10,000" and "events", e.g.
   * "10,000+ events". Defaults to "More than 10,000 events".
   */
  totalCapped?: (count: string, rows: string) => string;
  /** The date filter's words with no range chosen; defaults to "Last 90 days". */
  datePlaceholder?: string;
  /** What the panel says when the source's route is not available here. */
  unavailable?: { title: string; description: string };
  /** What is exported, as the export menu says it: "event" or "entry". */
  exportNoun: string;
}

/** One field of the details dialog. */
export interface AuditTrailDetailField {
  label: string;
  value: string;
  /** A second, quieter line, e.g. a resource's kind or reference. */
  detail?: string;
  mono?: boolean;
}

/** A link from a row to the page of what it is about. */
export interface AuditTrailLink {
  href: string;
  label: string;
}

/** The Access log: who searched, viewed and exported the subject's data. */
export interface AuditTrailAccessSource {
  queryKey: readonly unknown[];
  list: (query: AuditTrailAccessListQuery) => Promise<AuditTrailAccessPage>;
  /** The kinds of read the activity filter offers. */
  activities: () => Promise<string[]>;
  export: (
    filters: AuditTrailAccessFilters,
    format: AuditTrailExportFormat,
  ) => Promise<AuditTrailExport>;
  /** One toast id, so a repeated refusal replaces the last. */
  exportErrorToastId: string;
  canView: (user: User) => boolean;
  filters: {
    read: (params: Pick<URLSearchParams, "get">) => AuditTrailAccessFilters;
    /** The view's whole query string with these filters. */
    write: (filters: AuditTrailAccessFilters) => string;
    has: (filters: AuditTrailAccessFilters) => boolean;
    rangeError: (filters: AuditTrailAccessFilters) => string | undefined;
  };
  results: readonly string[];
  codeLabel: (code: string) => string;
  activityLabel: (activity: string) => string;
  copy: AuditTrailListCopy &
    AuditTrailHeaderCopy & {
      /** What a read is of, e.g. "Resource or search". */
      target: string;
      targetPlaceholder: string;
    };
  views?: AuditTrailViews;
  viewId: string;
  /**
   * The route may not exist yet: the view switcher asks for `activities`
   * first and shows the Access view only when they arrive.
   */
  optional?: boolean;
}

/** The activity log: what changed, who did it, and whether it worked. */
export interface AuditTrailSource {
  queryKeys: { list: readonly unknown[]; options: readonly unknown[] };
  list: (query: AuditTrailListQuery) => Promise<AuditTrailPage>;
  /** The codes a filter offers; the platform lists hold the internal ones too. */
  options: (
    kind: AuditTrailOptionKind,
    platform: boolean,
    /** On the platform view, the organization picked, e.g. for its flags. */
    scope?: AuditTrailOptionScope,
  ) => Promise<readonly AuditTrailOption[]>;
  export: (
    filters: AuditTrailFilters,
    format: AuditTrailExportFormat,
    platform: boolean,
  ) => Promise<AuditTrailExport>;
  /** The platform view exports too; without it only the customer view does. */
  exportsPlatform?: boolean;
  /** One toast id, so a repeated refusal replaces the last. */
  exportErrorToastId: string;
  canView: (user: User, isSuperAdmin: boolean, platform: boolean) => boolean;
  canLoadOptions: (user: User, platform: boolean) => boolean;
  filters: {
    read: (
      params: Pick<URLSearchParams, "get">,
      platform: boolean,
    ) => AuditTrailFilters;
    /** The filters' query string; empty when there are none. */
    write: (filters: AuditTrailFilters, platform: boolean) => string;
    has: (filters: AuditTrailFilters) => boolean;
    rangeError: (
      filters: AuditTrailFilters,
      platform: boolean,
    ) => string | undefined;
  };
  codes: { results: readonly string[]; actorTypes: readonly string[] };
  /** A readable label for a server code. */
  codeLabel: (code: string) => string;
  /** What a row is about, e.g. "Credential · cred_8f2k". */
  resourceLabel: (entry: AuditTrailEntry) => string;
  /** The page of what a row is about, when it has one. */
  resourceHref?: (
    entry: AuditTrailEntry,
    platform: boolean,
  ) => string | undefined;
  /** The details dialog's link onward, e.g. to the certificate a row names. */
  relatedLink?: (
    entry: AuditTrailEntry,
    platform: boolean,
  ) => AuditTrailLink | undefined;
  /** Why a failed row failed, e.g. "Failed: You don't have permission". */
  failureLine?: (entry: AuditTrailEntry) => string | undefined;
  /**
   * Who the actor is beyond their name, e.g. "requested by Alice"; replaces
   * the default (the actor type, the job, the user CertPing acted for).
   */
  actorDetail?: (entry: AuditTrailEntry) => string | undefined;
  /**
   * The details dialog's resource field; undefined hides it (e.g. a sign-in,
   * which is about no named thing). Without it the dialog shows the kind
   * and the name, or "None".
   */
  resourceField?: (entry: AuditTrailEntry) => AuditTrailDetailField | undefined;
  /** More fields for the details dialog, e.g. how a member signed in. */
  detailFields?: (entry: AuditTrailEntry) => readonly AuditTrailDetailField[];
  /** A readable user agent, e.g. "Chrome 129 on macOS". */
  formatUserAgent?: (userAgent: string) => string;
  /** A category's label, e.g. "Credentials" for CREDENTIALS. */
  categoryLabel?: (category: string) => string;
  /**
   * The details dialog names the request and correlation ids apart; without
   * it a customer sees one "Reference ID".
   */
  separateReferences?: boolean;
  filterFields?: {
    customer: readonly AuditTrailFilterField[];
    platform: readonly AuditTrailFilterField[];
  };
  columns?: {
    customer: readonly AuditTrailColumnId[];
    platform: readonly AuditTrailColumnId[];
  };
  /** The date filter's presets; the 90-day one is the window when unset. */
  datePresets?: readonly AuditTrailDatePreset[];
  /** A line above the list, e.g. how far back the log reaches. */
  notice?: (context: AuditTrailNoticeContext) => AuditTrailNotice | undefined;
  copy: AuditTrailListCopy & {
    customer: AuditTrailHeaderCopy;
    platform: AuditTrailHeaderCopy;
    /** The resource column's header, e.g. "Resource". */
    resource: string;
    resourceFilter: { label: string; placeholder: string };
    /**
     * Past the last counted page of a capped total, e.g. "Showing the first
     * 10,000 matching entries. Narrow the filters to see older ones."
     */
    cappedHint?: (count: string) => string;
  };
  views?: AuditTrailViews;
  viewId: string;
  access?: AuditTrailAccessSource;
}
