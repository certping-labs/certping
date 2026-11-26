// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The shapes an audit trail is read in, whichever service records it. A
 * source (see `AuditTrailSource`) maps its own routes onto these.
 */

export const AUDIT_TRAIL_VISIBILITIES = ["CUSTOMER", "INTERNAL"] as const;
/** The platform view's choice to read customer and internal rows together. */
export const AUDIT_TRAIL_ALL_VISIBILITIES = "ALL";

export const AUDIT_TRAIL_EXPORT_FORMATS = ["csv", "json"] as const;
export type AuditTrailExportFormat =
  (typeof AUDIT_TRAIL_EXPORT_FORMATS)[number];

/**
 * One field an event changed. A null side was not recorded (a secret, or a
 * value too large to keep): the field changed, its value is not shown.
 */
export interface AuditTrailChange {
  field: string;
  before: string | null;
  after: string | null;
}

/** What a request row records of the request: the route pattern, never its values. */
export interface AuditTrailRequest {
  method: string;
  route: string;
  status: number;
  durationMs: number;
}

export interface AuditTrailEntry {
  id: number;
  timestamp: string;
  action: string;
  /** The event behind the action code, e.g. "certificate.renewed". */
  event?: string;
  /** A readable sentence, e.g. "Deleted the Azure credential 'prod-dns'". */
  summary: string;
  status: string;
  errorCode?: string;
  resource: string;
  resourceId?: number;
  /** The name of what the event is about, e.g. a certificate or a token. */
  resourceName?: string;
  actorType: string;
  /** Who acted: a user's name or email, a token's name, or "CertPing (system)". */
  actorName?: string;
  userId?: number;
  userEmail?: string;
  organizationId?: number;
  organizationName?: string;
  ipAddress?: string;
  requestId?: string;
  /** What support searches the logs by. */
  correlationId?: string;
  changes: AuditTrailChange[];
  /** The string attributes of the row's details, e.g. how a member signed in. */
  attributes: Record<string, string>;
  /** Platform view only: CUSTOMER, or INTERNAL for the request and job trail. */
  visibility?: string;
  /** Platform view only: who acted, as recorded, e.g. "system:trigger-renewals". */
  actor?: string;
  userAgent?: string;
  traceId?: string;
  request?: AuditTrailRequest;
  /**
   * Why a failed event failed, in words the customer can act on, rendered by
   * the server from `errorCode`; never an error's raw text.
   */
  reason?: string;
  /** The group the event is filtered by, e.g. "CREDENTIALS". */
  category?: string;
  /** A stable string reference of what the event is about, e.g. an xref. */
  resourceRef?: string;
  /** The event belongs to a feature that is off for the organization now. */
  featureOff?: boolean;
  /** On an automatic row: the member whose request CertPing carried out. */
  requestedByName?: string;
}

/**
 * A page of events, paged by keyset: `nextCursor` fetches the next page and is
 * absent on the last one.
 */
export interface AuditTrailPage {
  content: AuditTrailEntry[];
  /** Counted on the first page only, up to 10,000; see `totalCapped`. */
  totalElements: number;
  totalPages: number;
  totalCapped: boolean;
  nextCursor?: string;
  /**
   * Where the window the reader may see starts (ISO 8601); an earlier `from`
   * was clamped to it. Absent when the trail is not windowed.
   */
  visibleFrom?: string;
}

/** The filters an audit trail's list accepts; there is no sort or page number. */
export interface AuditTrailFilters {
  action?: string;
  resourceType?: string;
  status?: string;
  actorType?: string;
  resourceName?: string;
  /** The id of the resource the event is about, e.g. a certificate's id. */
  resourceId?: string;
  from?: string;
  to?: string;
  requestId?: string;
  correlationId?: string;
  organizationId?: string;
  /** The member who acted. */
  userId?: string;
  /** A category key, e.g. "CREDENTIALS". */
  category?: string;
  /**
   * A date preset relative to now, e.g. "7d"; the source turns it into
   * `from` when it reads, so a refresh keeps it relative. Never with from/to.
   */
  range?: string;
  /**
   * Platform view only: CUSTOMER (the default when absent), INTERNAL, or
   * AUDIT_TRAIL_ALL_VISIBILITIES for both.
   */
  visibility?: string;
}

/**
 * One read of the organization's data: what was searched, viewed or exported,
 * by whom, from where, and whether it was answered.
 */
export interface AuditTrailAccessEntry {
  id: number;
  timestamp: string;
  /** The kind of read, e.g. "access.audit_log_viewed". */
  activity: string;
  /** What was read, or a search's query. */
  target?: string;
  resourceId?: number;
  status: string;
  errorCode?: string;
  /** Who read: a member's email, or "Platform administrator" for CertPing's staff. */
  actor: string;
  /** Absent for CertPing's staff, as are the email and the address. */
  userId?: number;
  userEmail?: string;
  ipAddress?: string;
  requestId?: string;
  correlationId?: string;
}

/** A page of reads, keyset-paged like the events. */
export interface AuditTrailAccessPage {
  content: AuditTrailAccessEntry[];
  /** Counted on the first page only, up to 10,000; see `totalCapped`. */
  totalElements: number;
  totalPages: number;
  totalCapped: boolean;
  nextCursor?: string;
}

/** The filters an Access list accepts. */
export interface AuditTrailAccessFilters {
  activity?: string;
  userId?: string;
  /** What was read, or a search's query. */
  resourceName?: string;
  status?: string;
  from?: string;
  to?: string;
}

/** An exported log, as the server rendered it. */
export interface AuditTrailExport {
  blob: Blob;
  fileName: string;
}

/** An option a filter offers when its code alone does not say how it reads. */
export interface AuditTrailChoice {
  value: string;
  label: string;
}

/** The member filter's choice for events CertPing carried out itself. */
export const AUDIT_TRAIL_SYSTEM_MEMBER = "SYSTEM";
