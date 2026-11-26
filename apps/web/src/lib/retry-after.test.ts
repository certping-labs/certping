// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, AxiosHeaders } from "axios";

import { formatRetryWait, getRetryAfterSeconds } from "@/lib/retry-after";

const httpError = (status: number, retryAfter?: string): AxiosError => {
  const headers = new AxiosHeaders();
  if (retryAfter !== undefined) headers.set("Retry-After", retryAfter);
  const error = new AxiosError(`HTTP ${status}`);
  error.response = {
    status,
    statusText: "",
    headers,
    config: { headers: new AxiosHeaders() },
    data: {},
  };
  return error;
};

describe("getRetryAfterSeconds", () => {
  it.each([
    ["a 429 with whole seconds", httpError(429, "300"), 300],
    ["a 429 with a fraction, rounded up", httpError(429, "1.2"), 2],
    ["a 429 with no header", httpError(429), null],
    [
      "a 429 with an HTTP date",
      httpError(429, "Wed, 21 Oct 2026 07:28:00 GMT"),
      null,
    ],
    ["a 429 with zero", httpError(429, "0"), null],
    ["a 503 with the header", httpError(503, "30"), null],
    ["an error that is not from axios", new Error("boom"), null],
  ])("reads %s", (_, error, expected) => {
    expect(getRetryAfterSeconds(error)).toBe(expected);
  });
});

describe("formatRetryWait", () => {
  const now = Date.UTC(2026, 8, 26, 15, 0, 0);

  it("counts seconds for a short wait", () => {
    expect(formatRetryWait(now + 40_000, now)).toBe("Try again in 40 seconds.");
  });

  it("says one second, not one seconds", () => {
    expect(formatRetryWait(now + 400, now)).toBe("Try again in 1 second.");
  });

  it("names a clock time for a long wait", () => {
    expect(formatRetryWait(now + 3_600_000, now)).toMatch(
      /^Try again after \d{1,2}:\d{2}\s?[AP]M\.$/,
    );
  });
});
