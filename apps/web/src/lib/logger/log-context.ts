// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { LogMessage } from "@/types";

import {
  normalizeCorrelationId,
  readCorrelationId,
} from "@/lib/correlation-id";
import {
  sanitizeLogAttributes,
  sanitizeLogMessage,
  sanitizeLogText,
} from "@/lib/logger/log-sanitizer";

const EVENT_NAME_PATTERN = /^[a-z][a-z0-9]*(?:[._][a-z0-9]+)*$/;
const MAX_EVENT_NAME_LENGTH = 128;
const MAX_CLIENT_TIMESTAMP_SKEW_MS = 24 * 60 * 60 * 1000;

interface ErrorLike extends Record<string, unknown> {
  code?: unknown;
  config?: unknown;
  isAxiosError?: unknown;
  message?: unknown;
  name?: unknown;
  response?: unknown;
  stack?: unknown;
}

function readLogRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function isErrorLike(value: unknown): value is ErrorLike {
  return value instanceof Error || readLogRecord(value)?.isAxiosError === true;
}

function getErrorCandidate(
  metadata?: Record<string, unknown>,
): ErrorLike | undefined {
  return Object.values(metadata ?? {}).find(isErrorLike);
}

function readRecordString(
  record: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const value = record?.[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function getSafeUrlAttributes(
  config: Record<string, unknown>,
): Record<string, string> {
  const requestUrl = readRecordString(config, "url");
  if (!requestUrl) return {};

  try {
    const baseUrl = readRecordString(config, "baseURL");
    const fallbackBase = "https://unknown-backend.invalid";
    const parsedUrl = new URL(requestUrl, baseUrl || fallbackBase);
    return {
      "url.path": sanitizeLogText(parsedUrl.pathname, "url.path"),
      ...(parsedUrl.hostname === "unknown-backend.invalid"
        ? {}
        : {
            "server.address": sanitizeLogText(
              parsedUrl.hostname,
              "server.address",
            ),
          }),
    };
  } catch {
    return { "url.path": sanitizeLogText(requestUrl, "url.path") };
  }
}

function getHttpErrorAttributes(error: ErrorLike): Record<string, unknown> {
  const config = readLogRecord(error.config);
  const response = readLogRecord(error.response);
  const requestHeaders = config?.headers;
  const responseHeaders = response?.headers;
  const method = readRecordString(config, "method")?.toUpperCase();
  const status = response?.status;
  const correlationId =
    readCorrelationId(responseHeaders) ?? readCorrelationId(requestHeaders);

  return {
    ...(correlationId ? { "correlation.id": correlationId } : {}),
    ...(method ? { "http.request.method": method } : {}),
    ...(typeof status === "number"
      ? { "http.response.status_code": status, "error.type": String(status) }
      : {}),
    ...(config?._retry === true ? { "http.request.resend_count": 1 } : {}),
    ...(config ? getSafeUrlAttributes(config) : {}),
  };
}

function getExceptionAttributes(error?: ErrorLike): Record<string, unknown> {
  if (!error) return {};
  const name = typeof error.name === "string" ? error.name : "Error";
  const message = typeof error.message === "string" ? error.message : undefined;
  const stack = typeof error.stack === "string" ? error.stack : undefined;
  const code = typeof error.code === "string" ? error.code : undefined;
  const isAxiosError = error.isAxiosError === true;

  return {
    "exception.type": sanitizeLogText(name),
    ...(message ? { "exception.message": sanitizeLogText(message) } : {}),
    ...(stack ? { "exception.stacktrace": sanitizeLogText(stack) } : {}),
    ...(!isAxiosError
      ? { "error.type": sanitizeLogText(code || name) }
      : {
          "error.type": sanitizeLogText(code || name),
          ...getHttpErrorAttributes(error),
        }),
  };
}

function removeControlMetadata(
  metadata?: Record<string, unknown>,
): Record<string, unknown> | undefined {
  if (!metadata) return undefined;
  const attributes: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    const isControlField =
      key === "eventName" ||
      key === "correlationId" ||
      key === "correlation.id";
    if (!isControlField && !isErrorLike(value)) {
      attributes[key] = value === metadata ? "[Circular]" : value;
    }
  }
  return attributes;
}

export function normalizeEventName(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const eventName = value.trim();
  return eventName.length <= MAX_EVENT_NAME_LENGTH &&
    EVENT_NAME_PATTERN.test(eventName)
    ? eventName
    : undefined;
}

function getEventName(
  level: LogMessage["level"],
  metadata: Record<string, unknown> | undefined,
  error: ErrorLike | undefined,
): string | undefined {
  const explicitEventName = normalizeEventName(metadata?.eventName);
  if (explicitEventName) return explicitEventName;
  if (error?.isAxiosError === true) return "http.client.request.exception";
  if (error) return "exception";
  return level === "error" ? "application.error" : undefined;
}

function normalizeTimestamp(timestamp?: string): string {
  if (!timestamp) return new Date().toISOString();
  const parsedTimestamp = new Date(timestamp);
  const isValid = !Number.isNaN(parsedTimestamp.getTime());
  const isReasonable =
    isValid &&
    Math.abs(Date.now() - parsedTimestamp.getTime()) <=
      MAX_CLIENT_TIMESTAMP_SKEW_MS;
  return isReasonable
    ? parsedTimestamp.toISOString()
    : new Date().toISOString();
}

/** Builds a bounded, redacted, semantically structured log record. */
export function createLogMessage(
  level: LogMessage["level"],
  message: string,
  metadata?: Record<string, unknown>,
  timestamp?: string,
): LogMessage {
  const error = getErrorCandidate(metadata);
  const explicitCorrelationId = normalizeCorrelationId(
    metadata?.correlationId ?? metadata?.["correlation.id"],
  );
  const attributes = {
    ...(sanitizeLogAttributes(removeControlMetadata(metadata)) ?? {}),
    ...getExceptionAttributes(error),
    ...(explicitCorrelationId
      ? { "correlation.id": explicitCorrelationId }
      : {}),
  };

  return {
    level,
    message: sanitizeLogMessage(message),
    eventName: getEventName(level, metadata, error),
    meta: Object.keys(attributes).length > 0 ? attributes : undefined,
    timestamp: normalizeTimestamp(timestamp),
  };
}
