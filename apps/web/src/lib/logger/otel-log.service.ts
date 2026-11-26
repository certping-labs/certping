// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  logs,
  SeverityNumber,
  type AnyValueMap,
} from "@opentelemetry/api-logs";

import type { LogMessage } from "@/types";

const otelLogger = logs.getLogger("certping-pki-app");

const SEVERITY_NUMBERS: Record<LogMessage["level"], SeverityNumber> = {
  debug: SeverityNumber.DEBUG,
  info: SeverityNumber.INFO,
  warn: SeverityNumber.WARN,
  error: SeverityNumber.ERROR,
};

function toLogTimestamp(timestamp?: string): Date {
  const parsedTimestamp = timestamp ? new Date(timestamp) : new Date();
  return Number.isNaN(parsedTimestamp.getTime()) ? new Date() : parsedTimestamp;
}

/** Emits a structured OTel record on the server; browser logs use /web-api/logger. */
export function emitOtelLog(
  logMessage: LogMessage,
  source: "client" | "server",
): void {
  if (typeof window !== "undefined") {
    return;
  }

  otelLogger.emit({
    timestamp: toLogTimestamp(logMessage.timestamp),
    severityNumber: SEVERITY_NUMBERS[logMessage.level],
    severityText: logMessage.level.toUpperCase(),
    body: logMessage.message,
    eventName: logMessage.eventName,
    attributes: {
      "log.source": source,
      ...(logMessage.meta as AnyValueMap | undefined),
    },
  });
}
