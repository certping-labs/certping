// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from "next/server";

import type { LogMessage } from "@/types";

import { readCorrelationId } from "@/lib/correlation-id";
import { createLogMessage, normalizeEventName } from "@/lib/logger/log-context";

const MAX_CLIENT_LOG_PAYLOAD_BYTES = 32 * 1024;
const VALID_LEVELS: ReadonlySet<LogMessage["level"]> = new Set([
  "debug",
  "info",
  "warn",
  "error",
]);

export class ClientLogRequestError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ClientLogRequestError";
  }
}

function assertSupportedContentType(request: NextRequest): void {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) {
    throw new ClientLogRequestError(
      415,
      "Content-Type must be application/json",
    );
  }
}

function assertContentLengthWithinLimit(request: NextRequest): void {
  const contentLength = Number(request.headers.get("content-length"));
  if (
    Number.isFinite(contentLength) &&
    contentLength > MAX_CLIENT_LOG_PAYLOAD_BYTES
  ) {
    throw new ClientLogRequestError(413, "Log payload is too large");
  }
}

async function readBoundedBody(request: NextRequest): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) return "";

  const decoder = new TextDecoder();
  let body = "";
  let bytesRead = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) return body + decoder.decode();
    bytesRead += value.byteLength;
    if (bytesRead > MAX_CLIENT_LOG_PAYLOAD_BYTES) {
      await reader.cancel();
      throw new ClientLogRequestError(413, "Log payload is too large");
    }
    body += decoder.decode(value, { stream: true });
  }
}

function parseJsonObject(body: string): Record<string, unknown> {
  try {
    const payload: unknown = JSON.parse(body);
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      return payload as Record<string, unknown>;
    }
  } catch {
    // The caller receives one generic validation response for malformed JSON.
  }
  throw new ClientLogRequestError(400, "Invalid log data");
}

function getMetadata(payload: Record<string, unknown>) {
  const metadata = payload.meta;
  if (metadata === undefined) return undefined;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new ClientLogRequestError(400, "Invalid log metadata");
  }
  return metadata as Record<string, unknown>;
}

function getLevel(payload: Record<string, unknown>): LogMessage["level"] {
  const level = payload.level;
  if (
    typeof level === "string" &&
    VALID_LEVELS.has(level as LogMessage["level"])
  ) {
    return level as LogMessage["level"];
  }
  throw new ClientLogRequestError(400, "Invalid log level");
}

/** Reads and validates one untrusted browser log without unbounded buffering. */
export async function readClientLogMessage(
  request: NextRequest,
): Promise<LogMessage> {
  assertSupportedContentType(request);
  assertContentLengthWithinLimit(request);
  const payload = parseJsonObject(await readBoundedBody(request));
  if (typeof payload.message !== "string") {
    throw new ClientLogRequestError(400, "Invalid log message");
  }
  if (
    payload.eventName !== undefined &&
    !normalizeEventName(payload.eventName)
  ) {
    throw new ClientLogRequestError(400, "Invalid event name");
  }

  const requestCorrelationId = readCorrelationId(request.headers);
  const metadata = {
    ...(getMetadata(payload) ?? {}),
    ...(payload.eventName ? { eventName: payload.eventName } : {}),
    ...(requestCorrelationId ? { correlationId: requestCorrelationId } : {}),
  };
  return createLogMessage(
    getLevel(payload),
    payload.message,
    metadata,
    typeof payload.timestamp === "string" ? payload.timestamp : undefined,
  );
}
