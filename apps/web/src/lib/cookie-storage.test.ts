// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { CookieStorage } from "@/lib/cookie-storage";

describe("cookie-storage", () => {
  const originalDocument = Object.getOwnPropertyDescriptor(
    globalThis,
    "document",
  );

  afterEach(() => {
    if (originalDocument) {
      Object.defineProperty(globalThis, "document", originalDocument);
    } else {
      Reflect.deleteProperty(globalThis, "document");
    }
  });

  describe("set", () => {
    it("writes encoded cookie value with default path and expiry", () => {
      const mockDocument = { cookie: "" };
      Object.defineProperty(globalThis, "document", {
        value: mockDocument,
        configurable: true,
      });

      CookieStorage.set("displayName", "Ada Lovelace");

      expect(mockDocument.cookie).toContain("displayName=Ada%20Lovelace");
      expect(mockDocument.cookie).toContain("; path=/");
      expect(mockDocument.cookie).toContain("; expires=");
    });

    it("skips expiry when days is 0 and uses custom path", () => {
      const mockDocument = { cookie: "" };
      Object.defineProperty(globalThis, "document", {
        value: mockDocument,
        configurable: true,
      });

      CookieStorage.set("token", "abc123", 0, "/admin");

      expect(mockDocument.cookie).toBe("token=abc123; path=/admin");
    });

    it("does nothing when document is unavailable", () => {
      Reflect.deleteProperty(globalThis, "document");
      expect(() => CookieStorage.set("name", "value")).not.toThrow();
    });
  });

  describe("get", () => {
    it("returns decoded cookie value and supports leading spaces", () => {
      const mockDocument = {
        cookie: "theme=dark; user=Ada%20Lovelace; mode=on",
      };
      Object.defineProperty(globalThis, "document", {
        value: mockDocument,
        configurable: true,
      });

      expect(CookieStorage.get("user")).toBe("Ada Lovelace");
    });

    it("returns null for missing cookies or absent document", () => {
      const mockDocument = { cookie: "theme=dark" };
      Object.defineProperty(globalThis, "document", {
        value: mockDocument,
        configurable: true,
      });
      expect(CookieStorage.get("missing")).toBeNull();

      Reflect.deleteProperty(globalThis, "document");
      expect(CookieStorage.get("theme")).toBeNull();
    });
  });

  describe("remove", () => {
    it("writes max-age zero cookie for removal", () => {
      const mockDocument = { cookie: "" };
      Object.defineProperty(globalThis, "document", {
        value: mockDocument,
        configurable: true,
      });

      CookieStorage.remove("sessionId", "/secure");
      expect(mockDocument.cookie).toBe("sessionId=; Max-Age=0; path=/secure");
    });

    it("does nothing without document", () => {
      Reflect.deleteProperty(globalThis, "document");
      expect(() => CookieStorage.remove("sessionId")).not.toThrow();
    });
  });
});
