// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError } from "axios";
import { z } from "zod";

import { isNotFoundError } from "@/lib/http-errors";
import { errorReference, withReference } from "@/lib/correlation-id";
import { getErrorMessage } from "@/lib/utils";
import type { AuditTrailPage } from "@/types/audit-trail";

export type { AuditTrailExport } from "@/types/audit-trail";

// The server may send an absent value as null.
export const optionalString = z
  .string()
  .nullish()
  .transform((value) => value ?? undefined);
export const optionalNumber = z
  .number()
  .nullish()
  .transform((value) => value ?? undefined);

const detailsSchema = z.object({ attributes: z.record(z.unknown()) });

/** The string attributes of a row's details, a JSON string; none when it does not decode. */
export const readDetailAttributes = (
  details: string | null | undefined,
): Record<string, string> => {
  if (!details) {
    return {};
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(details);
  } catch {
    return {};
  }
  const parsed = detailsSchema.safeParse(decoded);
  if (!parsed.success) {
    return {};
  }
  const attributes: Record<string, string> = {};
  for (const [name, value] of Object.entries(parsed.data.attributes)) {
    if (typeof value === "string" && value.trim()) {
      attributes[name] = value;
    }
  }
  return attributes;
};

/** A change's side the server did not record (a secret) arrives as null. */
const changeSideSchema = z
  .string()
  .nullish()
  .transform((value) => value ?? null);

/**
 * One audit event as the server sends it; `details` decodes to its attributes.
 *
 * `actorType` SYSTEM is CertPing acting by itself and `actorName` already
 * reads as such ("CertPing (system)" or "CertPing (automatic)"); a super
 * admin's rows read "Platform administrator" to customers; the platform route's
 * `actor` names a job as "system:<job>"; `visibility` is CUSTOMER or INTERNAL
 * ("Internal" rows are the platform's request and job trail). Every field past
 * the server's AuditLogDto is optional, so an older server's rows parse too.
 */
export const auditTrailEntrySchema = z.object({
  id: z.number(),
  timestamp: z.string(),
  action: z.string(),
  event: optionalString,
  summary: z.string(),
  status: z.string(),
  errorCode: optionalString,
  resource: z.string(),
  resourceId: optionalNumber,
  resourceName: optionalString,
  actorType: z.string(),
  actorName: optionalString,
  userId: optionalNumber,
  userEmail: optionalString,
  organizationId: optionalNumber,
  organizationName: optionalString,
  ipAddress: optionalString,
  requestId: optionalString,
  correlationId: optionalString,
  changes: z
    .array(
      z.object({
        field: z.string(),
        before: changeSideSchema,
        after: changeSideSchema,
      }),
    )
    .nullish()
    .transform((value) => value ?? []),
  details: z
    .unknown()
    .transform((value) =>
      readDetailAttributes(typeof value === "string" ? value : undefined),
    ),
  // The platform route's own fields; the customer routes send none of them.
  visibility: optionalString,
  actor: optionalString,
  userAgent: optionalString,
  traceId: optionalString,
  request: z
    .object({
      method: z.string(),
      route: z.string(),
      status: z.number(),
      durationMs: z.number(),
    })
    .nullish()
    .transform((value) => value ?? undefined),
  // cert-manager's own fields.
  reason: optionalString,
  category: optionalString,
  resourceRef: optionalString,
  featureOff: z
    .boolean()
    .nullish()
    .transform((value) => value ?? undefined),
  requestedByName: optionalString,
});

export const auditTrailPageSchema = z.object({
  content: z.array(auditTrailEntrySchema),
  totalElements: z.number(),
  totalPages: z.number(),
  // An older service sends no flag: its total is exact.
  totalElementsCapped: z
    .boolean()
    .nullish()
    .transform((value) => value ?? false),
  nextCursor: optionalString,
  visibleFrom: optionalString,
});

/** A page of events as the server sends it; undefined when it is not one. */
export const parseAuditTrailPage = (
  data: unknown,
): AuditTrailPage | undefined => {
  const parsed = auditTrailPageSchema.safeParse(data);
  if (!parsed.success) {
    return undefined;
  }
  const page = parsed.data;
  return {
    content: page.content.map(({ details, ...entry }) => ({
      ...entry,
      attributes: details,
    })),
    totalElements: page.totalElements,
    totalPages: page.totalPages,
    totalCapped: page.totalElementsCapped,
    nextCursor: page.nextCursor,
    visibleFrom: page.visibleFrom,
  };
};

/**
 * A route the reader cannot use here: not deployed yet (404) or its feature is
 * off (423). A panel shows its source's explanation instead of an error.
 */
export class AuditTrailUnavailableError extends Error {
  constructor(message = "This audit log isn't available.") {
    super(message);
    this.name = "AuditTrailUnavailableError";
  }
}

export const isAuditTrailUnavailable = (
  error: unknown,
): error is AuditTrailUnavailableError =>
  error instanceof AuditTrailUnavailableError;

const LOCKED = 423;

/** Whether the server says the route does not exist or is switched off. */
export const isUnavailableResponse = (error: unknown): boolean =>
  isNotFoundError(error) ||
  (error instanceof AxiosError && error.response?.status === LOCKED);

/** The codes a filter offers. */
export const optionsSchema = z.array(z.string());

const isBlob = (value: unknown): value is Blob =>
  (typeof Blob !== "undefined" && value instanceof Blob) ||
  typeof (value as Blob | undefined)?.text === "function";

/** A blob's text; through FileReader where Blob has no text() (older engines). */
export const blobText = (blob: Blob): Promise<string> => {
  if (typeof blob.text === "function") {
    return blob.text();
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
};

const errorBodySchema = z.object({
  code: z.string().nullish(),
  message: z.string().nullish(),
});

/** What an export refusal says: its code, message and Retry-After, when set. */
export const readExportRefusal = async (
  error: unknown,
): Promise<{ code?: string; message?: string; retryAfter?: string }> => {
  if (!(error instanceof AxiosError)) {
    return {};
  }
  const body = await readErrorBody(error.response?.data);
  const headers = error.response?.headers as
    Record<string, unknown> | undefined;
  const retryAfter = headers?.["retry-after"];
  return {
    code: body?.code ?? undefined,
    message: body?.message ?? undefined,
    retryAfter:
      typeof retryAfter === "string" || typeof retryAfter === "number"
        ? String(retryAfter)
        : undefined,
  };
};

/** What an export refusal's body says: its code and message, when it says. */
const readErrorBody = async (
  body: unknown,
): Promise<z.infer<typeof errorBodySchema> | undefined> => {
  let decoded: unknown = body;
  if (isBlob(body)) {
    try {
      decoded = JSON.parse(await blobText(body));
    } catch {
      return undefined;
    }
  }
  const parsed = errorBodySchema.safeParse(decoded);
  return parsed.success ? parsed.data : undefined;
};

/**
 * Why an export was refused, in the user's words.
 *
 * Only a refusal with a `code` is the service's own, customer-safe words:
 * `messages` maps its code to what to say, else its `message` is shown. Any
 * other failure (a proxy's 502 or 504, Axios's "Request failed with status
 * code 502", a raw `error` string) reads "Couldn't export the log. Try
 * again." with the reference, when one is known.
 *
 * `uncodedMessages` shows the words of a refusal that carries customer-safe
 * words without a code. No caller sets it today.
 */
// With a blob response, an error body arrives as a Blob too.
export const readExportError = async (
  error: unknown,
  messages: Readonly<Record<string, string>> = {},
  { uncodedMessages = false }: { uncodedMessages?: boolean } = {},
): Promise<string> => {
  const fallback = "Couldn't export the log. Try again.";
  if (!(error instanceof AxiosError)) {
    return getErrorMessage(error, fallback);
  }
  const body = await readErrorBody(error.response?.data);
  if (body?.code) {
    return (
      messages[body.code] ||
      body.message ||
      withReference(fallback, errorReference(error))
    );
  }
  if (!uncodedMessages) {
    return withReference(fallback, errorReference(error));
  }
  if (isBlob(error.response?.data)) {
    return body?.message || fallback;
  }
  return getErrorMessage(error, fallback);
};
