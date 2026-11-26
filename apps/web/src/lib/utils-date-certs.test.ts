// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  formatCertDate,
  formatCertDateTime,
  formatDate,
  formatDateTime,
  formatDateTimeCompact,
  formatDateTimeDetailed,
  formatDateTimeWithSeconds,
  getCreatedAt,
  getExpiryLabel,
  getRemainingDays,
  getSSLStatusBadge,
  getUpdatedAt,
  getValidFrom,
  getValidTo,
  parseDateValue,
} from "@/lib/utils";

describe("utils date/certificate helpers", () => {
  it("parses date values and handles invalid input", () => {
    expect(parseDateValue("2026-01-01T00:00:00.000Z")).toBeInstanceOf(Date);
    expect(parseDateValue("invalid-date")).toBeNull();
    expect(parseDateValue(null)).toBeNull();
  });

  it("formats date and datetime variants", () => {
    const value = "2026-01-01T12:30:45.000Z";
    expect(formatDate(value)).toContain("2026");
    expect(formatDateTimeCompact(value)).toContain("2026");
    expect(formatDateTimeWithSeconds(value)).toContain("2026");
    expect(formatDateTimeDetailed(value)).toContain("2026");
    expect(formatDateTime(value)).toBe(formatDateTimeCompact(value));

    expect(formatDate(null)).toBe("-");
    expect(formatDateTimeCompact(null)).toBe("-");
    expect(formatDateTimeWithSeconds(undefined)).toBe("-");
    expect(formatDateTimeDetailed(undefined)).toBe("-");
  });

  it("computes remaining days and expiry labels", () => {
    expect(getRemainingDays(null)).toBeNull();

    const future = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
    const past = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const farFuture = new Date(
      Date.now() + 60 * 24 * 60 * 60 * 1000,
    ).toISOString();

    expect(getExpiryLabel(undefined)).toEqual({
      tone: "default",
      text: "Awaiting issuance",
    });
    expect(getExpiryLabel(past)).toEqual({
      tone: "critical",
      text: "Expired",
    });
    expect(getExpiryLabel(future)).toEqual({
      tone: "critical",
      text: expect.stringContaining("Expiring in"),
    });
    expect(getExpiryLabel(farFuture)).toEqual({
      tone: "default",
      text: expect.stringContaining("remaining"),
    });
    expect(
      getExpiryLabel(past, {
        expiredLabel: "Already expired",
      }),
    ).toEqual({
      tone: "critical",
      text: "Already expired",
    });
  });

  it("reads canonical and snake_case cert timestamp fields", () => {
    expect(
      getValidFrom({
        validFrom: "2026-01-01",
        valid_from: "ignored",
      }),
    ).toBe("2026-01-01");
    expect(getValidFrom({ valid_from: "2026-01-02" })).toBe("2026-01-02");
    expect(getValidFrom({})).toBeNull();

    expect(getValidTo({ validTo: "2026-02-01" })).toBe("2026-02-01");
    expect(getValidTo({ valid_to: "2026-02-02" })).toBe("2026-02-02");

    expect(getCreatedAt({ createdAt: "2026-03-01" })).toBe("2026-03-01");
    expect(getCreatedAt({ created_at: "2026-03-02" })).toBe("2026-03-02");

    expect(getUpdatedAt({ updatedAt: "2026-04-01" })).toBe("2026-04-01");
    expect(getUpdatedAt({ updated_at: "2026-04-02" })).toBe("2026-04-02");
  });

  it("formats certificate dates with N/A fallback", () => {
    expect(formatCertDate("2026-01-01T00:00:00.000Z")).not.toBe("N/A");
    expect(formatCertDate(undefined)).toBe("N/A");
    expect(formatCertDateTime("2026-01-01T00:00:00.000Z")).not.toBe("N/A");
    expect(formatCertDateTime(undefined)).toBe("N/A");
  });

  it("maps SSL status to badge tones", () => {
    expect(getSSLStatusBadge("active")).toBe("success");
    expect(getSSLStatusBadge("issued")).toBe("success");
    expect(getSSLStatusBadge("expired")).toBe("destructive");
    expect(getSSLStatusBadge("failed")).toBe("destructive");
    expect(getSSLStatusBadge("pending_dns")).toBe("warning");
    expect(getSSLStatusBadge("deploying")).toBe("default");
    expect(getSSLStatusBadge("unknown")).toBe("default");
  });
});
