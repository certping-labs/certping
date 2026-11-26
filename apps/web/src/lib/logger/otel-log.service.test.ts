/** @jest-environment node */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import * as otelApiLogs from "@opentelemetry/api-logs";

import { emitOtelLog } from "./otel-log.service";

jest.mock("@opentelemetry/api-logs", () => {
  const emit = jest.fn();
  return {
    logs: {
      getLogger: jest.fn(() => ({ emit })),
    },
    SeverityNumber: {
      DEBUG: 5,
      INFO: 9,
      WARN: 13,
      ERROR: 17,
    },
    testEmit: emit,
  };
});

it("emits structured log records with source and severity", () => {
  const testEmit = (otelApiLogs as typeof otelApiLogs & { testEmit: jest.Mock })
    .testEmit;

  emitOtelLog(
    {
      level: "error",
      message: "certificate request failed",
      eventName: "certificate.issue.exception",
      timestamp: "2026-07-13T12:00:00.000Z",
      meta: { requestId: "request-123" },
    },
    "server",
  );

  expect(testEmit).toHaveBeenCalledWith({
    timestamp: new Date("2026-07-13T12:00:00.000Z"),
    severityNumber: otelApiLogs.SeverityNumber.ERROR,
    severityText: "ERROR",
    body: "certificate request failed",
    eventName: "certificate.issue.exception",
    attributes: {
      "log.source": "server",
      requestId: "request-123",
    },
  });
});

it("replaces an invalid client timestamp", () => {
  const testEmit = (otelApiLogs as typeof otelApiLogs & { testEmit: jest.Mock })
    .testEmit;
  const beforeEmission = Date.now();

  emitOtelLog(
    {
      level: "warn",
      message: "invalid timestamp",
      timestamp: "not-a-date",
    },
    "client",
  );

  const emittedRecord = testEmit.mock.calls[0][0] as { timestamp: Date };
  expect(emittedRecord.timestamp.getTime()).toBeGreaterThanOrEqual(
    beforeEmission,
  );
});
