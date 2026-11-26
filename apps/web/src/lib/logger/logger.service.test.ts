/**
 * @jest-environment jsdom
 */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { LogMessage } from "@/types";

describe("logger.service", () => {
  const originalFetchDescriptor = Object.getOwnPropertyDescriptor(
    window,
    "fetch",
  );

  afterEach(() => {
    jest.restoreAllMocks();
    if (originalFetchDescriptor) {
      Object.defineProperty(window, "fetch", originalFetchDescriptor);
    }
    jest.resetModules();
  });

  it("sends sanitized payload to logger API in browser mode", async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    Object.defineProperty(window, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });
    const consoleSpy = jest
      .spyOn(console, "error")
      .mockImplementation(() => {});

    const { logger } = await import("./logger.service");

    const circularMeta: Record<string, unknown> = {
      scope: "test",
      correlationId: "corr-browser-123",
    };
    circularMeta.self = circularMeta;
    circularMeta.error = new Error("boom");

    await logger.error("logger payload test", circularMeta);

    expect(consoleSpy).toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, requestInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/web-api/logger");
    const payload = JSON.parse(String(requestInit.body)) as LogMessage;

    expect(payload.level).toBe("error");
    expect(payload.eventName).toBe("exception");
    expect(payload.meta?.scope).toBe("test");
    expect(payload.meta?.self).toBe("[Circular]");
    expect(payload.meta?.["exception.message"]).toBe("boom");
    expect(payload.meta?.["correlation.id"]).toBe("corr-browser-123");
    expect(requestInit.keepalive).toBe(true);
    expect(new Headers(requestInit.headers).get("X-Correlation-ID")).toBe(
      "corr-browser-123",
    );
  });

  it("warns when logger API rejects payload", async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 500 });
    Object.defineProperty(window, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const { logger } = await import("./logger.service");
    await logger.info("logger api fail");

    expect(warnSpy).toHaveBeenCalledWith("Logger API rejected log", {
      status: 500,
      level: "info",
    });
  });
});
