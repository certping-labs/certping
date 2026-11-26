// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  AxiosError,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from "axios";

import {
  isAccessDeniedError,
  isNotFoundError,
  isTransientRequestError,
} from "@/lib/http-errors";

function createAxiosError(status?: number): AxiosError {
  const error = new AxiosError("request failed");

  if (status !== undefined) {
    const response: AxiosResponse = {
      data: { message: "error" },
      status,
      statusText: "error",
      headers: {},
      config: { headers: {} } as InternalAxiosRequestConfig,
    };
    error.response = response;
  }

  return error;
}

describe("http-errors", () => {
  describe("isAccessDeniedError", () => {
    it("returns false for non-axios errors", () => {
      expect(isAccessDeniedError(new Error("boom"))).toBe(false);
    });

    it("returns false for axios errors without response status", () => {
      expect(isAccessDeniedError(createAxiosError())).toBe(false);
    });

    it("returns true only for 401 and 403", () => {
      expect(isAccessDeniedError(createAxiosError(401))).toBe(true);
      expect(isAccessDeniedError(createAxiosError(403))).toBe(true);
      expect(isAccessDeniedError(createAxiosError(404))).toBe(false);
      expect(isAccessDeniedError(createAxiosError(500))).toBe(false);
    });
  });

  describe("isNotFoundError", () => {
    it("returns false for non-axios errors", () => {
      expect(isNotFoundError({ message: "not axios" })).toBe(false);
    });

    it("returns true only for 404", () => {
      expect(isNotFoundError(createAxiosError(404))).toBe(true);
      expect(isNotFoundError(createAxiosError(403))).toBe(false);
      expect(isNotFoundError(createAxiosError())).toBe(false);
    });
  });

  describe("isTransientRequestError", () => {
    it("retries network and server-side failures", () => {
      expect(isTransientRequestError(new Error("network failed"))).toBe(true);
      expect(isTransientRequestError(createAxiosError())).toBe(true);
      expect(isTransientRequestError(createAxiosError(408))).toBe(true);
      expect(isTransientRequestError(createAxiosError(425))).toBe(true);
      expect(isTransientRequestError(createAxiosError(429))).toBe(true);
      expect(isTransientRequestError(createAxiosError(500))).toBe(true);
      expect(isTransientRequestError(createAxiosError(503))).toBe(true);
    });

    it("does not waste retries on permanent client errors", () => {
      expect(isTransientRequestError(createAxiosError(400))).toBe(false);
      expect(isTransientRequestError(createAxiosError(401))).toBe(false);
      expect(isTransientRequestError(createAxiosError(403))).toBe(false);
      expect(isTransientRequestError(createAxiosError(404))).toBe(false);
      expect(isTransientRequestError(createAxiosError(422))).toBe(false);
    });
  });
});
