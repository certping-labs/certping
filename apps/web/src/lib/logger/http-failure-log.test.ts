// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, AxiosHeaders } from "axios";

import { logger } from "@/lib/logger/logger.service";
import { logHttpClientFailure } from "@/lib/logger/http-failure-log";

jest.mock("@/lib/logger/logger.service", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

const mockedLogger = logger as unknown as jest.Mocked<
  Pick<typeof logger, "error" | "warn">
>;

function createAxiosError(status?: number, code = "ERR_BAD_RESPONSE") {
  const error = new AxiosError("request failed", code, {
    headers: new AxiosHeaders(),
    method: "get",
    url: "/api/v1/certificates",
  });
  if (status !== undefined) {
    error.response = {
      config: error.config!,
      data: {},
      headers: {},
      status,
      statusText: "failed",
    };
  }
  return error;
}

describe("HTTP failure logging", () => {
  it("warns when no response was received", () => {
    const error = createAxiosError(undefined, "ERR_NETWORK");
    expect(logHttpClientFailure(error)).toBe(true);
    expect(mockedLogger.warn).toHaveBeenCalledWith(
      "Backend request failed before a response was received",
      expect.objectContaining({
        eventName: "http.client.request.exception",
        error,
      }),
    );
  });

  it("logs server errors at error severity", () => {
    const error = createAxiosError(503);
    expect(logHttpClientFailure(error)).toBe(true);
    expect(mockedLogger.error).toHaveBeenCalledWith(
      "Backend request returned a server error",
      expect.objectContaining({ error }),
    );
  });

  it.each([408, 429])("warns for transient status %s", (status) => {
    const error = createAxiosError(status);
    expect(logHttpClientFailure(error)).toBe(true);
    expect(mockedLogger.warn).toHaveBeenCalledWith(
      "Backend request was throttled or timed out",
      expect.objectContaining({ error }),
    );
  });

  it("ignores routine client errors, cancellations, and non-Axios errors", () => {
    expect(logHttpClientFailure(createAxiosError(400))).toBe(false);
    expect(
      logHttpClientFailure(createAxiosError(undefined, "ERR_CANCELED")),
    ).toBe(false);
    expect(logHttpClientFailure(new Error("ordinary"))).toBe(false);
    expect(mockedLogger.error).not.toHaveBeenCalled();
    expect(mockedLogger.warn).not.toHaveBeenCalled();
  });
});
