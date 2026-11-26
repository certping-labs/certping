// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => ({
  apiClient: { post: jest.fn() },
  apiRoutes: {
    mutation: {
      certs: {
        export: (certificateXref: string) =>
          `/api/v1/certs/${encodeURIComponent(certificateXref)}/export`,
      },
    },
  },
}));

import {
  AxiosError,
  AxiosHeaders,
  type AxiosRequestHeaders,
  type AxiosResponse,
} from "axios";

import { apiClient } from "@/lib/api";
import {
  CERTIFICATE_EXPORT_TIMEOUT_MS,
  exportCertificate,
} from "@/lib/backend/certificate-export";
import { CertificateExportError } from "@/lib/cert-manager/certificate-export-errors";

const mockedPost = (apiClient as unknown as { post: jest.Mock }).post;

const PASSWORD = "correct horse battery";

const okResponse = (
  headers: Record<string, string>,
  body = "-----BEGIN CERTIFICATE-----",
): Partial<AxiosResponse<Blob>> => ({
  data: new Blob([body]),
  headers: new AxiosHeaders(headers),
  status: 200,
});

const blobError = (
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): AxiosError =>
  new AxiosError("Request failed", "ERR_BAD_REQUEST", undefined, undefined, {
    status,
    statusText: "error",
    headers,
    config: {
      headers: new AxiosHeaders({
        "X-Correlation-ID": "req-123",
      }) as AxiosRequestHeaders,
      data: JSON.stringify({ format: "PKCS12", password: PASSWORD }),
    },
    data: new Blob([typeof body === "string" ? body : JSON.stringify(body)], {
      type: "application/json",
    }),
  });

describe("exportCertificate", () => {
  it("posts a PEM request without a password and uses the server's file name", async () => {
    mockedPost.mockResolvedValue(
      okResponse({
        "content-disposition":
          'attachment; filename="example.com-fullchain.pem"',
      }),
    );

    const file = await exportCertificate(
      "cert 1",
      { format: "FULLCHAIN_PEM", password: "ignored", legacyPkcs12: true },
      { domain: "example.com", isWildcard: false },
    );

    expect(mockedPost).toHaveBeenCalledWith(
      "/api/v1/certs/cert%201/export",
      { format: "FULLCHAIN_PEM" },
      { responseType: "blob", timeout: CERTIFICATE_EXPORT_TIMEOUT_MS },
    );
    expect(file.fileName).toBe("example.com-fullchain.pem");
    await expect(file.blob.text()).resolves.toBe("-----BEGIN CERTIFICATE-----");
  });

  it("sends the password and legacy flag in the body for PKCS12", async () => {
    mockedPost.mockResolvedValue(okResponse({}));

    const file = await exportCertificate(
      "cert-1",
      { format: "PKCS12", password: PASSWORD },
      { domain: "example.com", isWildcard: true },
    );

    expect(mockedPost).toHaveBeenCalledWith(
      "/api/v1/certs/cert-1/export",
      { format: "PKCS12", password: PASSWORD, legacyPkcs12: false },
      { responseType: "blob", timeout: CERTIFICATE_EXPORT_TIMEOUT_MS },
    );
    expect(file.fileName).toBe("_wildcard.example.com.pfx");
  });

  it.each([
    ["no Content-Disposition (CORS hides it)", {}],
    ["an unreadable Content-Disposition", { "content-disposition": "inline" }],
    [
      "a Content-Disposition naming only dots",
      { "content-disposition": 'attachment; filename="..."' },
    ],
  ])(
    "names the file from the domain when the server sends %s",
    async (_label, headers) => {
      mockedPost.mockResolvedValue(okResponse(headers));

      const file = await exportCertificate(
        "cert-1",
        { format: "FULLCHAIN_PEM" },
        { domain: "Shop.Example.com", isWildcard: false },
      );

      expect(file.fileName).toBe("shop.example.com-fullchain.pem");
    },
  );

  it("falls back to a generic name without a domain", async () => {
    mockedPost.mockResolvedValue(okResponse({}));

    const file = await exportCertificate("cert-1", {
      format: "CERTIFICATE_PEM",
    });

    expect(file.fileName).toBe("certificate-cert.pem");
  });

  it("reads the header from a plain header map too", async () => {
    mockedPost.mockResolvedValue({
      data: new Blob(["key"]),
      headers: { "content-disposition": "attachment; filename=key.pem" },
    });

    const file = await exportCertificate("cert-1", {
      format: "PRIVATE_KEY_PEM",
    });

    expect(file.fileName).toBe("key.pem");
  });

  it("decodes the blob error body into a specific, password-free error", async () => {
    mockedPost.mockRejectedValue(
      blobError(409, { code: "CERT_NOT_EXPORTABLE", reason: "NOT_ACTIVE" }),
    );

    const error = await exportCertificate("cert-1", {
      format: "PKCS12",
      password: PASSWORD,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(CertificateExportError);
    expect(error).toMatchObject({
      status: 409,
      code: "CERT_NOT_EXPORTABLE",
      reason: "NOT_ACTIVE",
      message: "This certificate isn't active, so it can't be downloaded.",
    });
    expect(JSON.stringify(error)).not.toContain(PASSWORD);
    expect(Object.values(error as object)).not.toContainEqual(
      expect.objectContaining({ config: expect.anything() }),
    );
  });

  it("adds the correlation id to a material mismatch", async () => {
    mockedPost.mockRejectedValue(
      blobError(
        502,
        { code: "CERT_MATERIAL_MISMATCH" },
        {
          "x-correlation-id": "srv-789",
        },
      ),
    );

    await expect(
      exportCertificate("cert-1", { format: "CERTIFICATE_PEM" }),
    ).rejects.toThrow(
      "The stored certificate files don't match each other. Ask your CertPing administrator. (Reference: srv-789)",
    );
  });

  const KEY_DOWNLOADS_PAUSED =
    "Downloads that include the private key are temporarily unavailable. Try again shortly. (Reference: srv-503)";
  const CERTIFICATE_DOWNLOADS_PAUSED =
    "Certificate downloads are temporarily unavailable. Try again shortly. (Reference: srv-503)";

  it.each([
    ["PKCS12", KEY_DOWNLOADS_PAUSED],
    ["PRIVATE_KEY_PEM", KEY_DOWNLOADS_PAUSED],
    ["FULLCHAIN_PEM", CERTIFICATE_DOWNLOADS_PAUSED],
    ["CERTIFICATE_PEM", CERTIFICATE_DOWNLOADS_PAUSED],
  ] as const)(
    "words a 503 for the requested %s format",
    async (format, expected) => {
      mockedPost.mockRejectedValue(
        blobError(
          503,
          { code: "EXPORT_UNAVAILABLE" },
          { "x-correlation-id": "srv-503" },
        ),
      );

      const error = await exportCertificate("cert-1", {
        format,
        password: PASSWORD,
      }).catch((caught: unknown) => caught);

      expect(error).toMatchObject({ status: 503, format });
      expect((error as Error).message).toBe(expected);
      expect((error as Error).message).not.toMatch(/instead|another format/i);
    },
  );

  it("reports an unreachable server calmly", async () => {
    mockedPost.mockRejectedValue(new Error("Server is unreachable"));

    await expect(
      exportCertificate("cert-1", { format: "CERTIFICATE_PEM" }),
    ).rejects.toThrow("Couldn't reach CertPing");
  });
});
