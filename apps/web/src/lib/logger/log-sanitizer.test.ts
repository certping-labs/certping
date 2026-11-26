// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  sanitizeLogAttributes,
  sanitizeLogMessage,
  sanitizeLogText,
} from "@/lib/logger/log-sanitizer";

describe("log sanitizer", () => {
  it("redacts secrets, tokens, email addresses, and log injection characters", () => {
    expect(
      sanitizeLogMessage("failed\nuser@example.com Bearer abc.def-123\rnext"),
    ).toBe("failed\\n[REDACTED_EMAIL] Bearer [REDACTED]\\nnext");
    expect(
      sanitizeLogText(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature12345",
      ),
    ).toBe("[REDACTED_TOKEN]");
  });

  it("removes query strings and fragments from URL fields", () => {
    expect(
      sanitizeLogText(
        "https://api.example.com/reset?token=secret#fragment",
        "url.full",
      ),
    ).toBe("https://api.example.com/reset");
    expect(sanitizeLogText("/reset?token=secret", "href")).toBe("/reset");
  });

  it("sanitizes nested metadata into OTel-compatible values", () => {
    const circular: Record<string, unknown> = {
      authorization: "Bearer secret",
      authCode: "Xy7-transfer-code",
      userEmail: "person@example.com",
      createdAt: new Date("2026-07-14T00:00:00.000Z"),
      count: BigInt(10),
      callback: function namedCallback() {},
      marker: Symbol("marker"),
      invalidNumber: Number.POSITIVE_INFINITY,
      error: new Error("boom\nnext"),
      values: [1, "two"],
    };
    circular.self = circular;

    expect(sanitizeLogAttributes(circular)).toEqual(
      expect.objectContaining({
        authorization: "[REDACTED]",
        authCode: "[REDACTED]",
        userEmail: "[REDACTED]",
        createdAt: "2026-07-14T00:00:00.000Z",
        count: "10",
        callback: "[Function:namedCallback]",
        marker: "Symbol(marker)",
        invalidNumber: "Infinity",
        self: "[Circular]",
        values: [1, "two"],
        error: expect.objectContaining({ message: "boom\\nnext" }),
      }),
    );
  });

  it("bounds arrays, depth, entry count, and message length", () => {
    const manyEntries = Object.fromEntries(
      Array.from({ length: 70 }, (_, index) => [`field${index}`, index]),
    );
    const attributes = sanitizeLogAttributes({
      items: Array.from({ length: 25 }, (_, index) => index),
      nested: { a: { b: { c: { d: { e: "too deep" } } } } },
      ...manyEntries,
    });

    expect(attributes?.items).toHaveLength(20);
    expect(JSON.stringify(attributes)).toContain("[TRUNCATED]");
    expect(JSON.stringify(attributes)).toContain("attributesTruncated");
    expect(sanitizeLogMessage("x".repeat(2100))).toHaveLength(2000);
  });

  it("returns undefined for absent or empty attributes", () => {
    expect(sanitizeLogAttributes()).toBeUndefined();
    expect(sanitizeLogAttributes({})).toBeUndefined();
  });
});
