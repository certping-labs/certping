// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError } from "axios";
import { z } from "zod";

import type { AuditTrailOption } from "@/lib/audit-trail-source";
import { apiClient, apiRoutes } from "@/lib/api";
import {
  AuditTrailUnavailableError,
  blobText,
  isUnavailableResponse,
  optionalNumber,
  optionalString,
  optionsSchema,
  parseAuditTrailPage,
  readExportError,
  readExportRefusal,
} from "@/lib/backend/audit-trail";
import {
  getOrganizationIdValue,
  listOrganizations,
} from "@/lib/backend/organizations";
import { listUsers } from "@/lib/backend/users";
import { platformVisibilityParam } from "@/lib/audit-trail-filters";
import {
  AUDIT_MAX_PAGE_SIZE,
  auditCategoryLabel,
  presetStart,
} from "@/lib/cert-manager-audit-filters";
import { isNotFoundError } from "@/lib/http-errors";
import {
  AUDIT_TRAIL_SYSTEM_MEMBER,
  type AuditTrailAccessFilters,
  type AuditTrailAccessPage,
  type AuditTrailExport,
  type AuditTrailExportFormat,
  type AuditTrailFilters,
  type AuditTrailPage,
} from "@/types/audit-trail";

/**
 * The server's audit routes as the audit page reads them: the customer list
 * with `/actions`, `/resources` and `/categories`, `/audit-logs/export`,
 * `/audit-logs/access` (+ `/export`, `/activities`) and the super admin's
 * `/admin/audit-logs` (+ `/export`, `/actions`, `/resources`, `/categories`).
 * A route that answers 404 (an older server) reads here as "not available
 * yet", never as a failure.
 */

/** What the label of an automatic actor is in the member filter. */
export const AUTOMATIC_MEMBER_LABEL = "CertPing (automatic)";

const UNAVAILABLE = {
  platform:
    "Reading every organization's audit log arrives with the next CertPing update. Until then, switch into an organization to read its audit log.",
  locked:
    "Audit logs are turned off on this platform. CertPing keeps recording; the log shows here again once they are turned back on.",
  access: "The Access log arrives with the next CertPing update.",
  customer: "The audit log isn't available right now. Try again later.",
} as const;

const LIMIT_MESSAGE = "You've reached the limit of 10 exports an hour.";
const BUSY_MESSAGE = "Another export is running.";

/** The words for a refused export, by the refusal's code. */
export const AUDIT_EXPORT_MESSAGES: Readonly<Record<string, string>> = {
  EXPORT_TOO_LARGE:
    "More than 10,000 entries match. Narrow the filters or date range, then export again.",
  EXPORT_LIMIT: `${LIMIT_MESSAGE} Try again later.`,
  RATE_LIMITED: `${LIMIT_MESSAGE} Try again later.`,
  EXPORT_BUSY: `${BUSY_MESSAGE} Try again in a few seconds.`,
  EXPORT_IN_PROGRESS: `${BUSY_MESSAGE} Try again in a few seconds.`,
  EXPORT_NOT_RECORDED: "Couldn't start the export. Try again in a moment.",
  QUERY_TIMEOUT:
    "The export took too long. Narrow the filters or date range, then try again.",
};

/** Refusals that say when to come back (`Retry-After`), and how they say it. */
const RETRY_LEADS: Readonly<Record<string, string>> = {
  EXPORT_LIMIT: LIMIT_MESSAGE,
  RATE_LIMITED: LIMIT_MESSAGE,
  EXPORT_BUSY: BUSY_MESSAGE,
  EXPORT_IN_PROGRESS: BUSY_MESSAGE,
};

/** An export cut short, by its row count or a JSON body that does not parse. */
export const EXPORT_ENDED_EARLY = "The export ended early — download it again.";

/** Retry-After (seconds or an HTTP date) as seconds from now; undefined when unreadable. */
export const retryAfterSeconds = (
  value: string | undefined,
  now: number = Date.now(),
): number | undefined => {
  const text = value?.trim();
  if (!text) {
    return undefined;
  }
  if (/^\d+$/.test(text)) {
    return Number(text);
  }
  const at = Date.parse(text);
  return Number.isNaN(at)
    ? undefined
    : Math.max(0, Math.ceil((at - now) / 1_000));
};

/** "in 45 seconds", "in about 12 minutes". */
const waitWords = (seconds: number): string => {
  if (seconds < 60) {
    const whole = Math.max(1, seconds);
    return `in ${whole} second${whole === 1 ? "" : "s"}`;
  }
  const minutes = Math.ceil(seconds / 60);
  return `in about ${minutes} minute${minutes === 1 ? "" : "s"}`;
};
const EXPORT_NOT_AVAILABLE = "Exporting the audit log isn't available yet.";

const LOCKED = 423;

/** A 404 or 423 as the page's "not available" state; anything else as it is. */
const unavailableOr = (error: unknown, message: string): unknown => {
  if (!isUnavailableResponse(error)) {
    return error;
  }
  const locked =
    error instanceof AxiosError && error.response?.status === LOCKED;
  return new AuditTrailUnavailableError(locked ? UNAVAILABLE.locked : message);
};

const filterParams = (
  filters: AuditTrailFilters,
  platform: boolean,
  now: number = Date.now(),
): Record<string, string> => {
  const params: Record<string, string> = {};
  const add = (key: string, value: string | undefined) => {
    const text = value?.trim();
    if (text) {
      params[key] = text;
    }
  };

  add("requestId", filters.requestId);
  add("userId", filters.userId);
  add("actorType", filters.actorType);
  add("category", filters.category);
  add("status", filters.status);
  add("action", filters.action);
  add("resourceType", filters.resourceType);
  add("resourceName", filters.resourceName);
  add("correlationId", filters.correlationId);
  if (filters.range) {
    add("from", presetStart(filters.range, now));
  } else {
    add("from", filters.from);
    add("to", filters.to);
  }
  // The customer routes read the session's organization and nothing else.
  if (platform) {
    add("organizationId", filters.organizationId);
    add("visibility", platformVisibilityParam(filters.visibility));
  }
  return params;
};

/** The request parameters of a list or export: exported for tests. */
export const auditFilterParams = filterParams;

export interface AuditListQuery {
  filters: AuditTrailFilters;
  platform: boolean;
  size: number;
  cursor?: string;
}

export const getAuditLogs = async ({
  filters,
  platform,
  size,
  cursor,
}: AuditListQuery): Promise<AuditTrailPage> => {
  const params: Record<string, string | number> = {
    ...filterParams(filters, platform),
    size: Math.min(size, AUDIT_MAX_PAGE_SIZE),
  };
  if (cursor) {
    params.cursor = cursor;
  }
  let data: unknown;
  try {
    const response = await apiClient.get<unknown>(
      platform
        ? apiRoutes.query.audit.platformList
        : apiRoutes.query.audit.list,
      { params },
    );
    data = response.data;
  } catch (error) {
    throw unavailableOr(
      error,
      platform ? UNAVAILABLE.platform : UNAVAILABLE.customer,
    );
  }
  const page = parseAuditTrailPage(data);
  if (!page) {
    throw new Error("Unexpected audit log response.");
  }
  return page;
};

const categorySchema = z.array(
  z.object({
    key: z.string(),
    label: z.string().nullish(),
    featureKey: z.string().nullish(),
    enabled: z.boolean().nullish(),
  }),
);

/**
 * The categories to filter by. Customers are sent only those of features on
 * for them, and are offered only those; a super admin sees every one, the
 * ones that are off marked so.
 */
const getCategories = async (
  platform: boolean,
  organizationId: string | undefined,
): Promise<AuditTrailOption[]> => {
  // A super admin's enabled flags are those of the organization they picked.
  const picked = platform ? organizationId?.trim() : undefined;
  const route = platform
    ? apiRoutes.query.audit.platformCategories
    : apiRoutes.query.audit.categories;
  const response = picked
    ? await apiClient.get<unknown>(route, {
        params: { organizationId: picked },
      })
    : await apiClient.get<unknown>(route);
  const parsed = categorySchema.safeParse(response.data);
  if (!parsed.success) {
    throw new Error("Unexpected audit category response.");
  }
  return parsed.data
    .filter((category) => platform || category.enabled !== false)
    .map((category) => {
      const label = category.label || auditCategoryLabel(category.key);
      return {
        value: category.key,
        label:
          platform && category.enabled === false
            ? `${label} (feature off)`
            : label,
      };
    });
};

/**
 * The organization's members, after "CertPing (automatic)". A reader who may
 * not list members still gets the automatic choice.
 */
const getMembers = async (): Promise<AuditTrailOption[]> => {
  const automatic = {
    value: AUDIT_TRAIL_SYSTEM_MEMBER,
    label: AUTOMATIC_MEMBER_LABEL,
  };
  try {
    const users = await listUsers(true);
    const members = users
      .map((user) => ({
        value: String(user.id),
        label: user.displayName?.trim() || user.email,
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
    return [automatic, ...members];
  } catch {
    return [automatic];
  }
};

const getOrganizations = async (): Promise<AuditTrailOption[]> => {
  const organizations = await listOrganizations();
  return organizations
    .map((organization) => ({
      value: getOrganizationIdValue(organization),
      label: organization.name,
    }))
    .sort((a, b) => a.label.localeCompare(b.label));
};

const getCodes = async (route: string): Promise<string[]> => {
  const response = await apiClient.get<unknown>(route);
  const parsed = optionsSchema.safeParse(response.data);
  if (!parsed.success) {
    throw new Error("Unexpected audit filter response.");
  }
  return parsed.data;
};

export type AuditOptionKind =
  "actions" | "resources" | "categories" | "members" | "organizations";

/** A filter's options; a list the server does not serve yet is empty. */
export const getAuditOptions = async (
  kind: AuditOptionKind,
  platform: boolean,
  scope: { organizationId?: string } = {},
): Promise<readonly AuditTrailOption[]> => {
  try {
    switch (kind) {
      case "categories":
        return await getCategories(platform, scope.organizationId);
      case "members":
        return await getMembers();
      case "organizations":
        return await getOrganizations();
      case "actions":
        return await getCodes(
          platform
            ? apiRoutes.query.audit.platformActions
            : apiRoutes.query.audit.actions,
        );
      case "resources":
        return await getCodes(
          platform
            ? apiRoutes.query.audit.platformResources
            : apiRoutes.query.audit.resources,
        );
      default:
        return [];
    }
  } catch (error) {
    if (isNotFoundError(error)) {
      return [];
    }
    throw error;
  }
};

const fileDate = (now: Date) => now.toISOString().slice(0, 10);

/** Turns a refused download into the words to show, with when to retry. */
const exportError = async (error: unknown): Promise<Error> => {
  if (isNotFoundError(error)) {
    return new Error(EXPORT_NOT_AVAILABLE);
  }
  // No response at all: the connection or the stream broke (e.g. an HTTP/2
  // stream reset mid-download), so whatever arrived is incomplete.
  if (error instanceof AxiosError && !error.response) {
    return new Error(EXPORT_ENDED_EARLY);
  }
  const refusal = await readExportRefusal(error);
  const lead = refusal.code ? RETRY_LEADS[refusal.code] : undefined;
  const wait = retryAfterSeconds(refusal.retryAfter);
  if (lead && wait !== undefined) {
    return new Error(`${lead} Try again ${waitWords(wait)}.`);
  }
  return new Error(await readExportError(error, AUDIT_EXPORT_MESSAGES));
};

/**
 * An RFC 4180 CSV as received: its data rows (records ended by a line break
 * outside quotes, less the header), and whether it ends where a record does.
 * A body cut mid-row lacks its final line break; one cut inside a quoted
 * field ends still inside quotes.
 */
export const readCsvRows = (
  text: string,
): { rows: number; complete: boolean } => {
  let lines = 0;
  let quoted = false;
  for (const char of text) {
    if (char === '"') {
      quoted = !quoted;
    } else if (char === "\n" && !quoted) {
      lines += 1;
    }
  }
  return {
    rows: Math.max(0, lines - 1),
    complete: text.length === 0 || (!quoted && text.endsWith("\n")),
  };
};

const ROWS_HEADER = "x-audit-export-rows";

/**
 * Refuses an export that arrived cut short: a JSON body that does not parse,
 * or fewer rows than the server counted (`X-Audit-Export-Rows`). The
 * header is only readable when CORS exposes it; without it a CSV is not
 * checked.
 */
const checkExportComplete = async (
  blob: Blob,
  format: AuditTrailExportFormat,
  headers: unknown,
): Promise<void> => {
  const raw = (headers as Record<string, unknown> | undefined)?.[ROWS_HEADER];
  const expected =
    raw === undefined || raw === null || String(raw).trim() === ""
      ? undefined
      : Number(raw);
  const counted = Number.isFinite(expected) ? expected : undefined;
  if (format === "json") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(await blobText(blob));
    } catch {
      throw new Error(EXPORT_ENDED_EARLY);
    }
    if (
      counted !== undefined &&
      Array.isArray(parsed) &&
      parsed.length !== counted
    ) {
      throw new Error(EXPORT_ENDED_EARLY);
    }
    return;
  }
  if (counted === undefined) {
    return;
  }
  const csv = readCsvRows(await blobText(blob));
  if (!csv.complete || csv.rows !== counted) {
    throw new Error(EXPORT_ENDED_EARLY);
  }
};

/** Downloads an export, refusing one that arrived cut short. */
const download = async (
  route: string,
  params: Record<string, string>,
  format: AuditTrailExportFormat,
  name: string,
): Promise<AuditTrailExport> => {
  let response: { data: Blob; headers?: unknown };
  try {
    response = await apiClient.get<Blob>(route, {
      params: { ...params, format },
      responseType: "blob",
    });
  } catch (error) {
    throw await exportError(error);
  }
  try {
    await checkExportComplete(response.data, format, response.headers);
  } catch {
    // A body that could not be read is as incomplete as a short one.
    throw new Error(EXPORT_ENDED_EARLY);
  }
  return {
    blob: response.data,
    fileName: `${name}-${fileDate(new Date(Date.now()))}.${format}`,
  };
};

/**
 * Exports every event the filters match, up to 10,000, as the server renders
 * it. The server allows an organization 10 exports an hour.
 */
export const exportAuditLogs = async (
  filters: AuditTrailFilters,
  format: AuditTrailExportFormat,
  platform: boolean,
): Promise<AuditTrailExport> =>
  download(
    platform
      ? apiRoutes.query.audit.platformExport
      : apiRoutes.query.audit.export,
    filterParams(filters, platform),
    format,
    "certping-audit-log",
  );

// The Access view. A row in the Access entry shape (activity, target, actor)
// or in the activity shape (event, resourceName, actorName) is read, so either
// rendering of a sensitive read parses.
const accessEntrySchema = z
  .object({
    id: z.number(),
    timestamp: z.string(),
    activity: optionalString,
    event: optionalString,
    target: optionalString,
    resourceName: optionalString,
    resourceId: optionalNumber,
    status: z.string(),
    errorCode: optionalString,
    actor: optionalString,
    actorName: optionalString,
    userId: optionalNumber,
    userEmail: optionalString,
    ipAddress: optionalString,
    requestId: optionalString,
    correlationId: optionalString,
  })
  .transform((entry) => ({
    id: entry.id,
    timestamp: entry.timestamp,
    activity: entry.activity ?? entry.event ?? "access",
    target: entry.target ?? entry.resourceName,
    resourceId: entry.resourceId,
    status: entry.status,
    errorCode: entry.errorCode,
    actor: entry.actor ?? entry.actorName ?? entry.userEmail ?? "Someone",
    userId: entry.userId,
    userEmail: entry.userEmail,
    ipAddress: entry.ipAddress,
    requestId: entry.requestId,
    correlationId: entry.correlationId,
  }));

const accessPageSchema = z.object({
  content: z.array(accessEntrySchema),
  totalElements: z.number(),
  totalPages: z.number(),
  totalElementsCapped: z
    .boolean()
    .nullish()
    .transform((value) => value ?? false),
  nextCursor: optionalString,
});

const ACCESS_FILTER_KEYS = [
  "activity",
  "userId",
  "resourceName",
  "status",
  "from",
  "to",
] as const satisfies readonly (keyof AuditTrailAccessFilters)[];

const accessParams = (
  filters: AuditTrailAccessFilters,
): Record<string, string> => {
  const params: Record<string, string> = {};
  for (const key of ACCESS_FILTER_KEYS) {
    const value = filters[key]?.trim();
    if (value) {
      params[key] = value;
    }
  }
  return params;
};

export const getAuditAccessLog = async ({
  filters,
  size,
  cursor,
}: {
  filters: AuditTrailAccessFilters;
  size: number;
  cursor?: string;
}): Promise<AuditTrailAccessPage> => {
  const params: Record<string, string | number> = {
    ...accessParams(filters),
    size: Math.min(size, AUDIT_MAX_PAGE_SIZE),
  };
  if (cursor) {
    params.cursor = cursor;
  }
  let data: unknown;
  try {
    const response = await apiClient.get<unknown>(
      apiRoutes.query.audit.accessList,
      { params },
    );
    data = response.data;
  } catch (error) {
    throw unavailableOr(error, UNAVAILABLE.access);
  }
  const parsed = accessPageSchema.safeParse(data);
  if (!parsed.success) {
    throw new Error("Unexpected audit access log response.");
  }
  const page = parsed.data;
  return {
    content: page.content,
    totalElements: page.totalElements,
    totalPages: page.totalPages,
    totalCapped: page.totalElementsCapped,
    nextCursor: page.nextCursor,
  };
};

/** The kinds of read the Access filter offers; a 404 reads as not available. */
export const getAuditAccessActivities = async (): Promise<string[]> => {
  try {
    return await getCodes(apiRoutes.query.audit.accessActivities);
  } catch (error) {
    throw unavailableOr(error, UNAVAILABLE.access);
  }
};

export const exportAuditAccessLog = async (
  filters: AuditTrailAccessFilters,
  format: AuditTrailExportFormat,
): Promise<AuditTrailExport> =>
  download(
    apiRoutes.query.audit.accessExport,
    accessParams(filters),
    format,
    "certping-access-log",
  );
