/** @jest-environment node */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { NextRequest } from "next/server";

import { emitOtelLog } from "@/lib/logger/otel-log.service";

import { POST } from "./route";

jest.mock("@/lib/logger/otel-log.service", () => ({ emitOtelLog: jest.fn() }));

describe("POST /web-api/logger", () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(new Date("2026-07-14T12:00:00.000Z"));
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  it("returns 400 for invalid payload", async () => {
    const request = createRequest({ foo: "bar" });
    const response = await POST(request);
    expect(response.status).toBe(400);
  });

  it("writes a redacted, correlated, structured client log", async () => {
    const infoSpy = jest.spyOn(console, "info").mockImplementation(() => {});
    const request = createRequest(
      {
        level: "info",
        message: "client-side info",
        eventName: "certificate.issue.completed",
        timestamp: "2026-07-14T11:59:00.000Z",
        meta: {
          feature: "cert-manager",
          authorization: "Bearer secret-token",
        },
      },
      { "X-Correlation-ID": "corr-route-123" },
    );

    const response = await POST(request);
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    const expectedLog = {
      level: "info",
      message: "client-side info",
      eventName: "certificate.issue.completed",
      timestamp: "2026-07-14T11:59:00.000Z",
      meta: {
        feature: "cert-manager",
        authorization: "[REDACTED]",
        "correlation.id": "corr-route-123",
      },
    };
    expect(infoSpy).toHaveBeenCalledWith("[client:info] client-side info", {
      source: "client",
      level: "info",
      "event.name": "certificate.issue.completed",
      timestamp: "2026-07-14T11:59:00.000Z",
      meta: expectedLog.meta,
    });
    expect(emitOtelLog).toHaveBeenCalledWith(expectedLog, "client");
  });

  it("routes debug logs to console.log", async () => {
    const logSpy = jest.spyOn(console, "log").mockImplementation(() => {});
    const response = await POST(
      createRequest({ level: "debug", message: "debug event" }),
    );

    expect(response.status).toBe(200);
    expect(logSpy).toHaveBeenCalledWith("[client:debug] debug event", {
      source: "client",
      level: "debug",
      "event.name": undefined,
      timestamp: "2026-07-14T12:00:00.000Z",
      meta: undefined,
    });
  });

  it.each([
    {
      name: "invalid metadata",
      payload: { level: "info", message: "event", meta: [] },
    },
    {
      name: "invalid event name",
      payload: { level: "info", message: "event", eventName: "Invalid Event" },
    },
    {
      name: "invalid level",
      payload: { level: "fatal", message: "event" },
    },
    { name: "invalid message", payload: { level: "info", message: 123 } },
  ])("returns 400 for $name", async ({ payload }) => {
    const response = await POST(createRequest(payload));
    expect(response.status).toBe(400);
  });

  it("returns 400 for malformed JSON", async () => {
    const request = new NextRequest("http://localhost/web-api/logger", {
      method: "POST",
      body: "{",
      headers: { "content-type": "application/json" },
    });
    expect((await POST(request)).status).toBe(400);
  });

  it("returns 415 for unsupported content types", async () => {
    const request = new NextRequest("http://localhost/web-api/logger", {
      method: "POST",
      body: "level=info",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    expect((await POST(request)).status).toBe(415);
  });

  it("returns 413 before reading a declared oversized payload", async () => {
    const request = createRequest(
      { level: "info", message: "event" },
      { "content-length": String(33 * 1024) },
    );
    expect((await POST(request)).status).toBe(413);
  });

  it("returns 500 for an unexpected stream failure", async () => {
    const error = new Error("stream failed");
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    const request = {
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader: () => ({ read: jest.fn().mockRejectedValue(error) }),
      },
    } as unknown as NextRequest;

    const response = await POST(request);
    expect(response.status).toBe(500);
    expect(errorSpy).toHaveBeenCalledWith("Logging error:", error);
  });
});

function createRequest(
  payload: unknown,
  additionalHeaders: Record<string, string> = {},
): NextRequest {
  return new NextRequest("http://localhost/web-api/logger", {
    method: "POST",
    body: JSON.stringify(payload),
    headers: {
      "content-type": "application/json",
      ...additionalHeaders,
    },
  });
}
