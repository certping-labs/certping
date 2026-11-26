// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, AxiosHeaders, type AxiosRequestHeaders } from "axios";

import {
  CertificateExportError,
  describeExportFailure,
  toCertificateExportError,
} from "@/lib/cert-manager/certificate-export-errors";

const httpError = (
  status: number,
  data: unknown,
  headers: Record<string, string> = {},
): AxiosError => {
  const config = {
    headers: new AxiosHeaders({
      "X-Correlation-ID": "req-1",
    }) as AxiosRequestHeaders,
  };
  return new AxiosError(
    "Request failed",
    "ERR_BAD_REQUEST",
    config,
    undefined,
    {
      status,
      statusText: "error",
      headers,
      config,
      data,
    },
  );
};

const failure = {
  format: null,
  code: null,
  reason: null,
  retryAfterSeconds: null,
  reference: undefined,
};

describe("toCertificateExportError", () => {
  it.each([
    [400, { code: "INVALID_EXPORT_REQUEST" }, "wasn't accepted"],
    [403, {}, "don't have permission"],
    [
      403,
      { code: "EXPORT_KEY_NOT_PERMITTED" },
      "You can download the certificate and chain, but not the private key.",
    ],
    [404, {}, "wasn't found in your organization"],
    [409, { code: "CERT_NOT_EXPORTABLE" }, "can't be downloaded"],
    [
      409,
      { code: "CERT_NOT_EXPORTABLE", reason: "NOT_LETS_ENCRYPT" },
      "doesn't support download",
    ],
    [
      409,
      { code: "CERT_NOT_EXPORTABLE", reason: "NOT_PLATFORM_STORED" },
      "your own key vault",
    ],
    [409, { error: { reason: "EXPIRED" } }, "has expired, so"],
    [409, { reason: "KEY_HELD_EXTERNALLY" }, "held outside CertPing"],
    [409, { reason: "NO_MATERIAL" }, "doesn't hold the files"],
    [409, { reason: "SOMETHING_NEW" }, "This certificate can't be downloaded."],
    [
      410,
      { code: "CERT_MATERIAL_GONE" },
      "CertPing no longer holds the files for this certificate.",
    ],
    [
      423,
      { feature: "CERTIFICATE_DOWNLOAD" },
      "isn't available. Ask your CertPing administrator.",
    ],
  ])("maps %i %j", (status, body, expected) => {
    expect(toCertificateExportError(httpError(status, body)).message).toContain(
      expected,
    );
  });

  it("uses the reference only where support needs it", () => {
    expect(toCertificateExportError(httpError(500, {})).message).toBe(
      "Couldn't download the certificate. Try again. (Reference: req-1)",
    );
    expect(
      toCertificateExportError(httpError(404, {})).reference,
    ).toBeUndefined();
  });

  it("tells the user when to retry a rate-limited download", () => {
    expect(
      toCertificateExportError(
        httpError(
          429,
          { code: "EXPORT_RATE_LIMITED" },
          { "retry-after": "61" },
        ),
      ).message,
    ).toBe(
      "You've reached the download limit for now. Try again in 2 minutes.",
    );
    expect(
      toCertificateExportError(
        httpError(429, {
          error: { code: "EXPORT_RATE_LIMITED", retryAfterSeconds: 30 },
        }),
      ).message,
    ).toContain("Try again in 1 minute.");
    expect(
      toCertificateExportError(httpError(429, {}, { "retry-after": "soon" }))
        .message,
    ).toBe("You've reached the download limit for now. Try again later.");
  });

  it("flags the refusals after which availability may have changed", () => {
    expect(
      toCertificateExportError(httpError(410, {})).changesAvailability,
    ).toBe(true);
    expect(
      toCertificateExportError(httpError(429, {})).changesAvailability,
    ).toBe(false);
    expect(
      toCertificateExportError(new Error("down")).changesAvailability,
    ).toBe(false);
  });

  it("returns an existing export error unchanged", () => {
    const error = new CertificateExportError({ ...failure, status: 410 });
    expect(toCertificateExportError(error)).toBe(error);
  });
});

describe("describeExportFailure", () => {
  it("names the unreachable case without a status", () => {
    expect(describeExportFailure({ ...failure, status: null })).toContain(
      "Couldn't reach CertPing",
    );
  });

  it.each([
    [
      "PKCS12",
      "Downloads that include the private key are temporarily unavailable. Try again shortly.",
    ],
    [
      "PRIVATE_KEY_PEM",
      "Downloads that include the private key are temporarily unavailable. Try again shortly.",
    ],
    [
      "FULLCHAIN_PEM",
      "Certificate downloads are temporarily unavailable. Try again shortly.",
    ],
    [
      "CERTIFICATE_PEM",
      "Certificate downloads are temporarily unavailable. Try again shortly.",
    ],
    [
      null,
      "Certificate downloads are temporarily unavailable. Try again shortly.",
    ],
  ] as const)(
    "explains a temporarily unavailable %s download, keeping the reference",
    (format, expected) => {
      expect(describeExportFailure({ ...failure, status: 503, format })).toBe(
        expected,
      );
      expect(
        describeExportFailure({
          ...failure,
          status: 503,
          format,
          reference: "srv-1",
        }),
      ).toBe(`${expected} (Reference: srv-1)`);
    },
  );

  it("flags a feature lock and a key held outside CertPing", () => {
    const locked = new CertificateExportError({ ...failure, status: 423 });
    expect(locked.isFeatureLocked).toBe(true);
    expect(locked.isKeyHeldExternally).toBe(false);
    const keyRefused = new CertificateExportError({
      ...failure,
      status: 409,
      reason: "KEY_HELD_EXTERNALLY",
    });
    expect(keyRefused.isFeatureLocked).toBe(false);
    expect(keyRefused.isKeyHeldExternally).toBe(true);
  });

  it("flags a private key the caller may not download only on its 403 code", () => {
    const keyNotPermitted = new CertificateExportError({
      ...failure,
      status: 403,
      code: "EXPORT_KEY_NOT_PERMITTED",
    });
    expect(keyNotPermitted.isKeyNotPermitted).toBe(true);
    expect(
      new CertificateExportError({ ...failure, status: 403 }).isKeyNotPermitted,
    ).toBe(false);
    expect(
      new CertificateExportError({
        ...failure,
        status: 409,
        code: "EXPORT_KEY_NOT_PERMITTED",
      }).isKeyNotPermitted,
    ).toBe(false);
  });

  it("explains a download turned off for the organization", () => {
    expect(
      describeExportFailure({
        ...failure,
        status: 409,
        reason: "FEATURE_DISABLED",
      }),
    ).toBe(
      "Certificate download isn't available. Ask your CertPing administrator.",
    );
  });

  it("asks for support on a mismatch even without a reference", () => {
    expect(describeExportFailure({ ...failure, status: 502 })).toBe(
      "The stored certificate files don't match each other. Ask your CertPing administrator.",
    );
  });
});
