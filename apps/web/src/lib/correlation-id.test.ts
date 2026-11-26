// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  CORRELATION_ID_HEADER,
  ensureCorrelationId,
  normalizeCorrelationId,
  readCorrelationId,
} from "@/lib/correlation-id";

const CORRELATION_ID_FORMAT =
  /^corr-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe("correlation ID helpers", () => {
  it("normalizes safe string and array values", () => {
    expect(normalizeCorrelationId(" corr-123 ")).toBe("corr-123");
    expect(normalizeCorrelationId(["corr-array"])).toBe("corr-array");
  });

  it.each([
    undefined,
    123,
    "",
    "bad correlation",
    "bad\nheader",
    `corr-${"x".repeat(128)}`,
  ])("rejects malformed value %p", (value) => {
    expect(normalizeCorrelationId(value)).toBeUndefined();
  });

  it("reads header maps case-insensitively", () => {
    expect(readCorrelationId({ "x-correlation-id": "corr-lower" })).toBe(
      "corr-lower",
    );
    expect(readCorrelationId(null)).toBeUndefined();
  });

  it("reads Headers-compatible accessors", () => {
    const headers = new Headers({ [CORRELATION_ID_HEADER]: "corr-headers" });
    expect(readCorrelationId(headers)).toBe("corr-headers");
  });

  it("preserves existing IDs", () => {
    const headers = { [CORRELATION_ID_HEADER]: "corr-existing" };
    expect(ensureCorrelationId(headers)).toBe("corr-existing");
    expect(headers[CORRELATION_ID_HEADER]).toBe("corr-existing");
  });

  it("adds IDs to plain maps and Headers-compatible accessors", () => {
    const headerMap: Record<string, unknown> = {};
    expect(ensureCorrelationId(headerMap)).toMatch(CORRELATION_ID_FORMAT);
    expect(headerMap[CORRELATION_ID_HEADER]).toMatch(CORRELATION_ID_FORMAT);

    const headers = new Headers();
    expect(ensureCorrelationId(headers)).toMatch(CORRELATION_ID_FORMAT);
    expect(headers.get(CORRELATION_ID_HEADER)).toMatch(CORRELATION_ID_FORMAT);
  });

  it("returns a generated ID when no mutable header container exists", () => {
    expect(ensureCorrelationId(undefined)).toMatch(CORRELATION_ID_FORMAT);
  });

  it("gives every call its own ID", () => {
    const first: Record<string, unknown> = {};
    const second: Record<string, unknown> = {};

    expect(ensureCorrelationId(first)).not.toBe(ensureCorrelationId(second));
  });
});
