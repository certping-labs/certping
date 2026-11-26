// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, type AxiosRequestHeaders } from "axios";

import {
  getApiErrorCode,
  getApiErrorMessage,
  getApiResponseMessage,
  getApiRetryAfterSeconds,
  isUuid,
  rethrowWithDecodedBlobError,
} from "@/lib/backend/common";

describe("backend common helpers", () => {
  describe("rethrowWithDecodedBlobError", () => {
    const blobError = (body: string) =>
      new AxiosError(
        "Request failed",
        "ERR_BAD_REQUEST",
        undefined,
        undefined,
        {
          status: 400,
          statusText: "Bad Request",
          headers: {},
          config: { headers: {} as AxiosRequestHeaders },
          data: new Blob([body], { type: "application/json" }),
        },
      );

    it("exposes the JSON message hidden inside a blob error body", async () => {
      const error = blobError(
        JSON.stringify({ message: "Validation failed: phoneNumber: Invalid" }),
      );

      await expect(rethrowWithDecodedBlobError(error)).rejects.toBe(error);
      expect(getApiErrorMessage(error, "fallback")).toBe(
        "Validation failed: phoneNumber: Invalid",
      );
    });

    it("falls back to the status message for a non-JSON body", async () => {
      const error = blobError("<html>Bad Gateway</html>");

      await expect(rethrowWithDecodedBlobError(error)).rejects.toBe(error);
      expect(getApiErrorMessage(error, "fallback")).toBe("Request failed");
    });

    it("rethrows non-blob errors untouched", async () => {
      const error = new Error("boom");
      await expect(rethrowWithDecodedBlobError(error)).rejects.toBe(error);
    });
  });

  describe("getApiErrorMessage", () => {
    it("returns fallback for unknown non-error values", () => {
      expect(getApiErrorMessage({ unknown: true }, "fallback")).toBe(
        "fallback",
      );
    });

    it("returns message for standard Error objects", () => {
      expect(getApiErrorMessage(new Error("boom"), "fallback")).toBe("boom");
    });

    it("extracts the first field error message for Axios errors", () => {
      const axiosError = new AxiosError(
        "Request failed",
        "ERR_BAD_REQUEST",
        undefined,
        undefined,
        {
          status: 400,
          statusText: "Bad Request",
          headers: {},
          config: { headers: {} as AxiosRequestHeaders },
          data: {
            message: "generic",
            fieldErrors: [{ field: "domain", message: "Domain is required" }],
          },
        },
      );

      expect(getApiErrorMessage(axiosError, "fallback")).toBe(
        "Domain is required",
      );
    });

    it("extracts nested data message for Axios errors", () => {
      const axiosError = new AxiosError(
        "Request failed",
        "ERR_BAD_REQUEST",
        undefined,
        undefined,
        {
          status: 400,
          statusText: "Bad Request",
          headers: {},
          config: { headers: {} as AxiosRequestHeaders },
          data: {
            data: {
              detail: "Nested detail message",
            },
          },
        },
      );

      expect(getApiErrorMessage(axiosError, "fallback")).toBe(
        "Nested detail message",
      );
    });

    it("falls back to Axios error.message when payload has no extractable message", () => {
      const axiosError = new AxiosError(
        "Network down",
        "ERR_NETWORK",
        undefined,
        undefined,
        {
          status: 503,
          statusText: "Service Unavailable",
          headers: {},
          config: { headers: {} as AxiosRequestHeaders },
          data: { unexpected: true },
        },
      );

      expect(getApiErrorMessage(axiosError, "fallback")).toBe("Network down");
    });
  });

  describe("public error envelope", () => {
    const envelope = (error: unknown) =>
      new AxiosError(
        "Request failed with status code 429",
        "ERR_BAD_REQUEST",
        undefined,
        undefined,
        {
          status: 429,
          statusText: "Too Many Requests",
          headers: {},
          config: { headers: {} as AxiosRequestHeaders },
          data: { error },
        },
      );

    it("reads the message, code and retry delay from a nested error", () => {
      const error = envelope({
        code: "RATE_LIMIT_EXCEEDED",
        message: "Only 2 requests are allowed per minute.",
        retryAfterSeconds: 41,
      });

      expect(getApiErrorMessage(error, "fallback")).toBe(
        "Only 2 requests are allowed per minute.",
      );
      expect(getApiResponseMessage(error)).toBe(
        "Only 2 requests are allowed per minute.",
      );
      expect(getApiErrorCode(error)).toBe("RATE_LIMIT_EXCEEDED");
      expect(getApiRetryAfterSeconds(error)).toBe(41);
    });

    it("still reads a plain string error and a top-level code", () => {
      const error = new AxiosError(
        "Request failed",
        "ERR_BAD_REQUEST",
        undefined,
        undefined,
        {
          status: 409,
          statusText: "Conflict",
          headers: {},
          config: { headers: {} as AxiosRequestHeaders },
          data: { error: "Conflict", code: "FINDING_CLEARED" },
        },
      );

      expect(getApiErrorMessage(error, "fallback")).toBe("Conflict");
      expect(getApiErrorCode(error)).toBe("FINDING_CLEARED");
      expect(getApiRetryAfterSeconds(error)).toBeNull();
    });

    it("has no response message or retry delay for a non-API error", () => {
      expect(getApiResponseMessage(new Error("boom"))).toBeNull();
      expect(getApiRetryAfterSeconds(new Error("boom"))).toBeNull();
      expect(getApiResponseMessage(envelope({}))).toBeNull();
    });
  });

  describe("isUuid", () => {
    it("validates RFC-compatible UUID format", () => {
      expect(isUuid("123e4567-e89b-12d3-a456-426614174000")).toBe(true);
      expect(isUuid("not-a-uuid")).toBe(false);
      expect(isUuid(undefined)).toBe(false);
    });
  });
});
