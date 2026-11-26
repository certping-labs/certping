// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { generateCorrelationId } from "@/lib/api-helpers";

export const CORRELATION_ID_HEADER = "X-Correlation-ID";

const MAX_CORRELATION_ID_LENGTH = 128;
const VALID_CORRELATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

interface HeaderAccessor {
  get(name: string): unknown;
  set?(name: string, value: string): unknown;
}

function isHeaderAccessor(value: unknown): value is HeaderAccessor {
  return (
    typeof value === "object" &&
    value !== null &&
    "get" in value &&
    typeof value.get === "function"
  );
}

/** Returns a safe correlation ID or undefined for malformed input. */
export function normalizeCorrelationId(value: unknown): string | undefined {
  const candidate = Array.isArray(value) ? value[0] : value;
  if (typeof candidate !== "string") {
    return undefined;
  }

  const correlationId = candidate.trim();
  if (
    correlationId.length === 0 ||
    correlationId.length > MAX_CORRELATION_ID_LENGTH ||
    !VALID_CORRELATION_ID_PATTERN.test(correlationId)
  ) {
    return undefined;
  }
  return correlationId;
}

/** Reads a correlation ID from AxiosHeaders, Headers, or a plain header map. */
export function readCorrelationId(headers: unknown): string | undefined {
  if (isHeaderAccessor(headers)) {
    return normalizeCorrelationId(headers.get(CORRELATION_ID_HEADER));
  }
  if (!headers || typeof headers !== "object") {
    return undefined;
  }

  const entry = Object.entries(headers).find(
    ([name]) => name.toLowerCase() === CORRELATION_ID_HEADER.toLowerCase(),
  );
  return normalizeCorrelationId(entry?.[1]);
}

/** Preserves an existing correlation ID or adds a new one to mutable headers. */
export function ensureCorrelationId(headers: unknown): string {
  const existingCorrelationId = readCorrelationId(headers);
  if (existingCorrelationId) {
    return existingCorrelationId;
  }

  const correlationId = generateCorrelationId();
  if (isHeaderAccessor(headers) && headers.set) {
    headers.set(CORRELATION_ID_HEADER, correlationId);
  } else if (headers && typeof headers === "object") {
    (headers as Record<string, unknown>)[CORRELATION_ID_HEADER] = correlationId;
  }
  return correlationId;
}

/** Statuses the customer resolves alone: what to fix is in the message, so no reference is shown. */
const SELF_SERVICE_STATUSES = new Set([400, 401, 403, 404, 422]);

interface FailedApiCall {
  /** Set on a failure with no response, which has no headers left to read the ID from. */
  correlationId?: unknown;
  response?: { status?: number; headers?: unknown; data?: unknown };
  config?: { headers?: unknown };
}

/** A failure with no response, carrying the correlation ID its request was sent with. */
export function unreachableError(
  message: string,
  requestHeaders: unknown,
): Error {
  return Object.assign(new Error(message), {
    correlationId: readCorrelationId(requestHeaders),
  });
}

/**
 * The reference a customer quotes to support for a failed API call: the correlation ID the server
 * answered with, else the one its error body names, else the one the call was sent with.
 */
export function errorReference(error: unknown): string | undefined {
  const failed = error as FailedApiCall;
  const status = failed.response?.status;
  if (status !== undefined && SELF_SERVICE_STATUSES.has(status)) {
    return undefined;
  }
  const body = failed.response?.data as { correlationId?: unknown } | undefined;
  return (
    readCorrelationId(failed.response?.headers) ??
    normalizeCorrelationId(body?.correlationId) ??
    readCorrelationId(failed.config?.headers) ??
    normalizeCorrelationId(failed.correlationId)
  );
}

/** Appends the reference to an error message, once, when there is one. */
export function withReference(message: string, reference?: string): string {
  const suffix = `(Reference: ${reference})`;
  return !reference || message.endsWith(suffix)
    ? message
    : `${message} ${suffix}`;
}
