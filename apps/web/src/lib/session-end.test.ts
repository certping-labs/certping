// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, type AxiosResponse } from "axios";

import { getAccountRefusal } from "@/lib/session-end";
import { getLoginPath, parseSignedOutReason } from "@/lib/signed-out-reason";

jest.mock("@/lib/logger/logger.service", () => ({
  logger: { warn: jest.fn(), error: jest.fn() },
}));

function httpError(status: number, data: unknown): AxiosError {
  return new AxiosError("HTTP error", undefined, undefined, undefined, {
    status,
    data,
  } as AxiosResponse);
}

describe("getAccountRefusal", () => {
  it.each([
    [{ message: "Account is disabled or deleted" }, "account-disabled"],
    [{ error: "Account is disabled or deleted" }, "account-disabled"],
    [
      {
        error: "Unauthorized",
        message: "Organization is suspended or inactive",
      },
      "organization-suspended",
    ],
    [
      { error: "Organization is suspended or inactive" },
      "organization-suspended",
    ],
  ])("reads the reason from a 401 body %p", (data, reason) => {
    expect(getAccountRefusal(httpError(401, data))).toBe(reason);
  });

  it.each([
    ["an expired token", { message: "Invalid or expired token" }],
    ["a revoked token", { error: "Token has been revoked" }],
    ["a prototype key", { message: "constructor" }],
    ["no body", undefined],
    ["a string body", "Account is disabled or deleted"],
    ["a non-string message", { message: 401 }],
  ])("leaves %s to the refresh path", (_case, data) => {
    expect(getAccountRefusal(httpError(401, data))).toBeNull();
  });

  it("ignores the message on any status but 401", () => {
    expect(
      getAccountRefusal(
        httpError(403, { message: "Account is disabled or deleted" }),
      ),
    ).toBeNull();
  });

  it("ignores an error that is not an HTTP answer", () => {
    expect(
      getAccountRefusal(new Error("Account is disabled or deleted")),
    ).toBeNull();
  });
});

describe("parseSignedOutReason", () => {
  it.each(["account-disabled", "organization-suspended"])(
    "accepts %p",
    (value) => {
      expect(parseSignedOutReason(value)).toBe(value);
    },
  );

  it.each([undefined, "", "expired", ["account-disabled"], "toString"])(
    "rejects %p",
    (value) => {
      expect(parseSignedOutReason(value)).toBeNull();
    },
  );
});

describe("getLoginPath", () => {
  it("names the reason in the sign-in URL", () => {
    expect(getLoginPath("organization-suspended")).toBe(
      "/login?signedOut=organization-suspended",
    );
  });

  it("is plain sign-in without a reason", () => {
    expect(getLoginPath()).toBe("/login");
  });
});
