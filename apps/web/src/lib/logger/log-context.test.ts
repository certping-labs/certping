// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { createLogMessage, normalizeEventName } from "@/lib/logger/log-context";

describe("log context", () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(new Date("2026-07-14T12:00:00.000Z"));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("extracts correlation and HTTP context from Axios errors", () => {
    const axiosError = {
      name: "AxiosError",
      message: "Request failed with status code 503",
      stack: "AxiosError: failed\n at request",
      code: "ERR_BAD_RESPONSE",
      isAxiosError: true,
      config: {
        baseURL: "https://api.example.com",
        url: "/api/v1/certificates?token=sensitive",
        method: "post",
        _retry: true,
        headers: { "X-Correlation-ID": "corr-request" },
      },
      response: {
        status: 503,
        headers: { "x-correlation-id": "corr-response" },
      },
    };

    const logMessage = createLogMessage("error", "Backend failed", {
      error: axiosError,
      operation: "certificate.issue",
    });

    expect(logMessage).toEqual(
      expect.objectContaining({
        level: "error",
        message: "Backend failed",
        eventName: "http.client.request.exception",
        timestamp: "2026-07-14T12:00:00.000Z",
        meta: expect.objectContaining({
          operation: "certificate.issue",
          "correlation.id": "corr-response",
          "http.request.method": "POST",
          "http.request.resend_count": 1,
          "http.response.status_code": 503,
          "server.address": "api.example.com",
          "url.path": "/api/v1/certificates",
          "error.type": "503",
          "exception.type": "AxiosError",
          "exception.message": "Request failed with status code 503",
          "exception.stacktrace": "AxiosError: failed\\n at request",
        }),
      }),
    );
    expect(logMessage.meta).not.toHaveProperty("error");
  });

  it("uses explicit event and correlation context when supplied", () => {
    const logMessage = createLogMessage("warn", "retry exhausted", {
      eventName: "certificate.issue.exception",
      correlationId: "corr-explicit",
      error: {
        name: "AxiosError",
        message: "failed",
        isAxiosError: true,
        config: {
          url: "/api/v1/certificates",
          headers: { "X-Correlation-ID": "corr-request" },
        },
      },
    });

    expect(logMessage.eventName).toBe("certificate.issue.exception");
    expect(logMessage.meta?.["correlation.id"]).toBe("corr-explicit");
    expect(logMessage.meta?.["error.type"]).toBe("AxiosError");
  });

  it("maps ordinary exceptions to standard exception attributes", () => {
    const error = new TypeError("bad input");
    const logMessage = createLogMessage("error", "operation failed", {
      error,
      password: "must-not-leak",
    });

    expect(logMessage.eventName).toBe("exception");
    expect(logMessage.meta).toEqual(
      expect.objectContaining({
        password: "[REDACTED]",
        "error.type": "TypeError",
        "exception.type": "TypeError",
        "exception.message": "bad input",
      }),
    );
  });

  it("uses an application event for errors without exception objects", () => {
    expect(createLogMessage("error", "failed").eventName).toBe(
      "application.error",
    );
    expect(createLogMessage("info", "completed").eventName).toBeUndefined();
  });

  it("validates event names and client timestamps", () => {
    expect(normalizeEventName(" certificate.issue.completed ")).toBe(
      "certificate.issue.completed",
    );
    expect(normalizeEventName("Invalid Event")).toBeUndefined();
    expect(normalizeEventName(123)).toBeUndefined();
    expect(normalizeEventName(`a${"b".repeat(128)}`)).toBeUndefined();

    expect(
      createLogMessage("info", "recent", undefined, "2026-07-14T11:59:00.000Z")
        .timestamp,
    ).toBe("2026-07-14T11:59:00.000Z");
    expect(
      createLogMessage("info", "invalid", undefined, "not-a-date").timestamp,
    ).toBe("2026-07-14T12:00:00.000Z");
    expect(
      createLogMessage("info", "stale", undefined, "2020-01-01T00:00:00.000Z")
        .timestamp,
    ).toBe("2026-07-14T12:00:00.000Z");
  });

  it("drops malformed explicit correlation IDs", () => {
    const logMessage = createLogMessage("info", "event", {
      "correlation.id": "bad\nvalue",
    });
    expect(logMessage.meta).toBeUndefined();
  });
});
