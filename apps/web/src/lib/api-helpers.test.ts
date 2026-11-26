// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  generateCorrelationId,
  normalizeExpiresInMs,
  normalizeOrganizationIds,
} from "@/lib/api-helpers";

describe("api-helpers", () => {
  describe("normalizeExpiresInMs", () => {
    it("defaults to 1h when invalid", () => {
      expect(normalizeExpiresInMs(undefined)).toBe(3600 * 1000);
      expect(normalizeExpiresInMs(0)).toBe(3600 * 1000);
      expect(normalizeExpiresInMs(-1)).toBe(3600 * 1000);
      expect(normalizeExpiresInMs(Number.NaN)).toBe(3600 * 1000);
    });

    it("treats large values as milliseconds and small values as seconds", () => {
      expect(normalizeExpiresInMs(90)).toBe(90 * 1000);
      expect(normalizeExpiresInMs(200_000)).toBe(200_000);
    });
  });

  describe("correlation id helpers", () => {
    const format =
      /^corr-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

    function withCrypto(value: unknown, run: () => void) {
      const originalCrypto = globalThis.crypto;
      Object.defineProperty(globalThis, "crypto", {
        value,
        configurable: true,
      });
      try {
        run();
      } finally {
        Object.defineProperty(globalThis, "crypto", {
          value: originalCrypto,
          configurable: true,
        });
      }
    }

    it("generates random ids that do not repeat", () => {
      const ids = new Set(
        Array.from({ length: 1000 }, () => generateCorrelationId()),
      );

      expect(ids.size).toBe(1000);
      for (const id of ids) {
        expect(id).toMatch(format);
      }
    });

    it("uses the platform's randomUUID when it has one", () => {
      withCrypto(
        { randomUUID: () => "0af76519-16cd-43dd-8448-eb211c80319c" },
        () => {
          expect(generateCorrelationId()).toBe(
            "corr-0af76519-16cd-43dd-8448-eb211c80319c",
          );
        },
      );
    });

    it("keeps the format when randomUUID throws or crypto is missing", () => {
      withCrypto(
        {
          randomUUID: () => {
            throw new Error("boom");
          },
        },
        () => {
          expect(generateCorrelationId()).toMatch(format);
        },
      );
      withCrypto(undefined, () => {
        expect(generateCorrelationId()).toMatch(format);
      });
    });
  });

  describe("normalizeOrganizationIds", () => {
    it("converts numeric organization ids throughout JSON payloads", () => {
      expect(
        normalizeOrganizationIds({
          organizationId: "1",
          nested: [{ organizationId: " 42 " }],
        }),
      ).toEqual({
        organizationId: 1,
        nested: [{ organizationId: 42 }],
      });
    });

    it("preserves UUID-like ids and non-JSON payloads", () => {
      const formData = new FormData();

      expect(normalizeOrganizationIds({ organizationId: "org-uuid" })).toEqual({
        organizationId: "org-uuid",
      });
      expect(normalizeOrganizationIds(formData)).toBe(formData);
    });
  });
});
