// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import {
  AUTH_URLS,
  PASSWORD_REGEX,
  copyToClipboard,
  decodeJWT,
  formatZodErrors,
  getDaysFromTimeRange,
  getRootDomain,
  normalizeUrl,
  sanitizeDomain,
  validatePasswordStrenght,
} from "@/lib/utils";

const jwtDecodeMock = jest.fn();
const loggerErrorMock = jest.fn();

jest.mock("jwt-decode", () => ({
  jwtDecode: (...args: unknown[]) => jwtDecodeMock(...args),
}));

jest.mock("@/lib/logger/logger.service", () => ({
  logger: {
    error: (...args: unknown[]) => loggerErrorMock(...args),
  },
}));

describe("utils auth/password helpers", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("normalizes URLs by adding protocol only when missing", () => {
    expect(normalizeUrl("example.com")).toBe("https://example.com");
    expect(normalizeUrl("https://example.com")).toBe("https://example.com");
  });

  it("decodes JWT payload and logs decode failures", () => {
    jwtDecodeMock.mockReturnValueOnce({ sub: "user@example.com" });
    expect(decodeJWT<{ sub: string }>("token")?.sub).toBe("user@example.com");

    jwtDecodeMock.mockImplementationOnce(() => {
      throw new Error("bad token");
    });
    expect(decodeJWT("bad-token")).toBeNull();
    expect(loggerErrorMock).toHaveBeenCalled();
  });

  it("validates password strength and sets error payloads", () => {
    const setError = jest.fn();

    expect(validatePasswordStrenght({ value: "", setError })).toBe(true);
    expect(setError).toHaveBeenCalledWith(null);

    setError.mockReset();
    expect(validatePasswordStrenght({ value: "weak", setError })).toBe(false);
    expect(setError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: "Password must meet all requirements",
      }),
    );

    setError.mockReset();
    expect(
      validatePasswordStrenght({
        value: "StrongPassword!1",
        setError,
      }),
    ).toBe(true);
    expect(setError).toHaveBeenCalledWith(null);
  });

  it("supports time-range and regex/constants helpers", () => {
    expect(getDaysFromTimeRange("90d")).toBe(90);
    expect(getDaysFromTimeRange("30d")).toBe(30);
    expect(getDaysFromTimeRange("7d")).toBe(7);
    expect(getDaysFromTimeRange("unknown")).toBe(7);

    expect(PASSWORD_REGEX.test("StrongPassword!1")).toBe(true);
    expect(PASSWORD_REGEX.test("weak")).toBe(false);
    expect(AUTH_URLS).toEqual(["/login", "/setup"]);
  });

  it("formats zod errors as path map and message string", () => {
    const schema = z.object({
      email: z.string().email(),
      nested: z.object({
        count: z.number().min(1),
      }),
    });
    const result = schema.safeParse({
      email: "invalid",
      nested: { count: 0 },
    });

    if (result.success) {
      throw new Error("Expected schema parse to fail");
    }

    expect(formatZodErrors(result.error)).toEqual({
      email: "Invalid email address",
      "nested.count": "Too small: expected number to be >=1",
    });
    expect(formatZodErrors(undefined)).toBeNull();
  });

  it("formats root domain", () => {
    expect(getRootDomain("api.dev.example.com")).toBe("example.com");
    expect(getRootDomain("example.com")).toBe("example.com");
  });

  it("copies to clipboard and sanitizes domains", async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });

    copyToClipboard("hello");
    expect(writeText).toHaveBeenCalledWith("hello");

    expect(sanitizeDomain("https://www.example.com/path")).toBe(
      "www.example.com",
    );
    expect(sanitizeDomain("HTTPS://www.example.com/path")).toBe(
      "www.example.com",
    );
    expect(sanitizeDomain("httpbin.org")).toBe("httpbin.org");
    expect(() => sanitizeDomain("::::")).toThrow("Invalid domain format");
  });
});
