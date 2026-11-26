// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

const MAX_ATTRIBUTE_DEPTH = 5;
const MAX_ATTRIBUTE_ENTRIES = 64;
const MAX_ARRAY_ITEMS = 20;
const MAX_ATTRIBUTE_STRING_LENGTH = 4000;
const MAX_LOG_MESSAGE_LENGTH = 2000;

const REDACTED_VALUE = "[REDACTED]";
const TRUNCATED_VALUE = "[TRUNCATED]";
const SENSITIVE_KEY_SUFFIX_PATTERN =
  /(authcode|authorization|cookie|credential|email|password|passwd|privatekey|secret|sessionid|token)$/;
const BEARER_TOKEN_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const JWT_PATTERN =
  /\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const LINE_BREAK_PATTERN = /[\r\n\u2028\u2029]+/g;

interface SanitizationState {
  entries: number;
  readonly seen: WeakSet<object>;
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_SUFFIX_PATTERN.test(normalizeKey(key));
}

function sanitizeUrl(value: string): string {
  try {
    const parsedUrl = new URL(value, "https://log-sanitizer.invalid");
    const isRelativeUrl = parsedUrl.hostname === "log-sanitizer.invalid";
    return isRelativeUrl
      ? parsedUrl.pathname
      : `${parsedUrl.origin}${parsedUrl.pathname}`;
  } catch {
    return value.split(/[?#]/, 1)[0];
  }
}

/** Removes secrets, PII, log-injection characters, and excessive text. */
export function sanitizeLogText(value: string, key = ""): string {
  const withoutUrlParameters = /(^|\.)(href|url)(\.|$)/i.test(key)
    ? sanitizeUrl(value)
    : value;
  return withoutUrlParameters
    .replace(BEARER_TOKEN_PATTERN, "Bearer [REDACTED]")
    .replace(JWT_PATTERN, "[REDACTED_TOKEN]")
    .replace(EMAIL_PATTERN, "[REDACTED_EMAIL]")
    .replace(LINE_BREAK_PATTERN, "\\n")
    .slice(0, MAX_ATTRIBUTE_STRING_LENGTH);
}

function sanitizeObject(
  value: object,
  depth: number,
  state: SanitizationState,
): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  for (const [key, childValue] of Object.entries(value)) {
    if (state.entries >= MAX_ATTRIBUTE_ENTRIES) {
      sanitized.attributesTruncated = true;
      break;
    }
    state.entries += 1;
    sanitized[key] = isSensitiveKey(key)
      ? REDACTED_VALUE
      : sanitizeValue(childValue, key, depth + 1, state);
  }
  return sanitized;
}

function sanitizeValue(
  value: unknown,
  key: string,
  depth: number,
  state: SanitizationState,
): unknown {
  if (typeof value === "string") return sanitizeLogText(value, key);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function")
    return `[Function:${value.name || "anonymous"}]`;
  if (typeof value === "symbol") return value.toString();
  if (typeof value === "number")
    return Number.isFinite(value) ? value : String(value);
  if (value === null || typeof value !== "object") return value;
  if (value instanceof Date) return value.toISOString();
  if (depth >= MAX_ATTRIBUTE_DEPTH) return TRUNCATED_VALUE;
  if (state.seen.has(value)) return "[Circular]";
  state.seen.add(value);

  if (value instanceof Error) {
    return sanitizeObject(
      { name: value.name, message: value.message, stack: value.stack },
      depth,
      state,
    );
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_ARRAY_ITEMS)
      .map((item) => sanitizeValue(item, key, depth + 1, state));
  }
  return sanitizeObject(value, depth, state);
}

/** Converts arbitrary metadata into bounded OTel-compatible attributes. */
export function sanitizeLogAttributes(
  attributes?: Record<string, unknown>,
): Record<string, unknown> | undefined {
  if (!attributes) return undefined;
  const state: SanitizationState = { entries: 0, seen: new WeakSet() };
  state.seen.add(attributes);
  const sanitized = sanitizeObject(attributes, 0, state);
  return Object.keys(sanitized).length > 0 ? sanitized : undefined;
}

/** Produces a single-line, bounded log body. */
export function sanitizeLogMessage(message: string): string {
  return sanitizeLogText(message).slice(0, MAX_LOG_MESSAGE_LENGTH);
}
