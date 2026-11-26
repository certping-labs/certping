// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, AxiosHeaders } from "axios";
import type { InternalAxiosRequestConfig } from "axios";

import {
  errorReference,
  unreachableError,
  withReference,
} from "@/lib/correlation-id";
import { getErrorMessage } from "@/lib/utils";

function apiError(
  status: number,
  data: unknown,
  responseHeaders: Record<string, string> = {},
  sentCorrelationId = "corr-sent",
): AxiosError {
  const config = {
    headers: new AxiosHeaders({ "X-Correlation-ID": sentCorrelationId }),
  } as InternalAxiosRequestConfig;
  return new AxiosError("Request failed", "ERR_BAD_RESPONSE", config, null, {
    status,
    statusText: "",
    data,
    headers: responseHeaders,
    config,
  });
}

describe("the reference on an error message", () => {
  it("is the correlation ID the server answered with", () => {
    const error = apiError(
      500,
      { message: "Something went wrong", correlationId: "corr-body" },
      { "x-correlation-id": "corr-answered" },
    );

    expect(errorReference(error)).toBe("corr-answered");
    expect(getErrorMessage(error, "Failed")).toBe(
      "Something went wrong (Reference: corr-answered)",
    );
  });

  it("falls back to the error body's, then to the one the call was sent with", () => {
    expect(errorReference(apiError(502, { correlationId: "corr-body" }))).toBe(
      "corr-body",
    );
    expect(errorReference(apiError(409, { message: "Conflict" }))).toBe(
      "corr-sent",
    );
  });

  it.each([400, 401, 403, 404, 422])(
    "is left off a %i, which the customer resolves alone",
    (status) => {
      const error = apiError(status, { message: "Name is required" });

      expect(errorReference(error)).toBeUndefined();
      expect(getErrorMessage(error, "Failed")).toBe("Name is required");
    },
  );

  it("never shows a malformed ID", () => {
    const error = apiError(
      500,
      { message: "Broken" },
      { "x-correlation-id": "bad id\n" },
      "also bad",
    );

    expect(getErrorMessage(error, "Failed")).toBe("Broken");
  });

  it("leaves a message with no reference as it is", () => {
    expect(withReference("Saved", undefined)).toBe("Saved");
    expect(getErrorMessage(new Error("Offline"), "Failed")).toBe("Offline");
  });

  it("is still shown when the server never answered", () => {
    const error = unreachableError("Server is unreachable", {
      "X-Correlation-ID": "corr-sent",
    });

    expect(error.message).toBe("Server is unreachable");
    expect(getErrorMessage(error, "Failed")).toBe(
      "Server is unreachable (Reference: corr-sent)",
    );
  });

  it("is never appended twice", () => {
    const once = withReference("Something went wrong", "corr-1");

    expect(withReference(once, "corr-1")).toBe(once);
    expect(
      getErrorMessage(
        apiError(500, { message: once }, { "x-correlation-id": "corr-1" }),
        "Failed",
      ),
    ).toBe("Something went wrong (Reference: corr-1)");
  });
});
