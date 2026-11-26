// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  CERTIFICATE_EXPORT_FORMAT_OPTIONS,
  certificateExportFormSchema,
  getDefaultExportFormValues,
  getExportFormatOptions,
  PFX_PASSWORD_CHARSET_MESSAGE,
  toCertificateExportRequest,
  type CertificateExportFormValues,
} from "@/lib/cert-manager/certificate-export-form";
import {
  isCertificateExportAvailable,
  parseCertificateExportAvailability,
  parseExportUnavailableReason,
  withExportAvailability,
} from "@/lib/cert-manager/certificate-export-availability";
import type { SSLCertificateDetails } from "@/types/ssl";

const pfx = (
  overrides: Partial<CertificateExportFormValues>,
): CertificateExportFormValues => ({
  format: "PKCS12",
  password: "longenough",
  confirmPassword: "longenough",
  legacyPkcs12: false,
  ...overrides,
});

const issuesOf = (values: CertificateExportFormValues) => {
  const result = certificateExportFormSchema.safeParse(values);
  return result.success
    ? []
    : result.error.issues.map((issue) => [issue.path[0], issue.message]);
};

describe("certificate export form", () => {
  it("needs no password for PEM formats", () => {
    expect(issuesOf(pfx({ format: "FULLCHAIN_PEM", password: "" }))).toEqual(
      [],
    );
  });

  it("needs no password for DER or PKCS#7 either", () => {
    expect(issuesOf(pfx({ format: "CERTIFICATE_DER", password: "" }))).toEqual(
      [],
    );
    expect(issuesOf(pfx({ format: "PKCS7", password: "" }))).toEqual([]);
  });

  it("enforces the PFX password bounds and confirmation", () => {
    expect(issuesOf(pfx({}))).toEqual([]);
    expect(
      issuesOf(pfx({ password: "short", confirmPassword: "short" })),
    ).toEqual([["password", "Use at least 8 characters."]]);
    const long = "x".repeat(129);
    expect(issuesOf(pfx({ password: long, confirmPassword: long }))).toEqual([
      ["password", "Use 128 characters or fewer."],
    ]);
    expect(issuesOf(pfx({ confirmPassword: "different" }))).toEqual([
      ["confirmPassword", "The passwords don't match."],
    ]);
  });

  it("accepts only printable ASCII PFX passwords", () => {
    const printable = Array.from({ length: 0x7e - 0x20 + 1 }, (_, i) =>
      String.fromCharCode(0x20 + i),
    ).join("");
    expect(
      issuesOf(pfx({ password: printable, confirmPassword: printable })),
    ).toEqual([]);
    for (const password of [
      "pässwordx",
      "password€€",
      "password🔑🔑",
      "pass\u00a0word",
    ]) {
      expect(issuesOf(pfx({ password, confirmPassword: password }))).toEqual([
        ["password", PFX_PASSWORD_CHARSET_MESSAGE],
      ]);
    }
  });

  it("builds the request body for each format", () => {
    expect(
      toCertificateExportRequest(pfx({ format: "PRIVATE_KEY_PEM" })),
    ).toEqual({ format: "PRIVATE_KEY_PEM" });
    expect(toCertificateExportRequest(pfx({ legacyPkcs12: true }))).toEqual({
      format: "PKCS12",
      password: "longenough",
      legacyPkcs12: true,
    });
  });

  it("offers the backend's formats in a fixed order", () => {
    expect(getExportFormatOptions(undefined)).toBe(
      CERTIFICATE_EXPORT_FORMAT_OPTIONS,
    );
    expect(getExportFormatOptions([])).toBe(CERTIFICATE_EXPORT_FORMAT_OPTIONS);
    expect(
      getExportFormatOptions(["PKCS12", "CERTIFICATE_PEM"]).map(
        (option) => option.format,
      ),
    ).toEqual(["CERTIFICATE_PEM", "PKCS12"]);
  });

  it("drops the private-key formats once the backend refused the key", () => {
    const formatsOf = (options: ReturnType<typeof getExportFormatOptions>) =>
      options.map((option) => option.format);
    expect(
      formatsOf(getExportFormatOptions(undefined, { withoutPrivateKey: true })),
    ).toEqual(["FULLCHAIN_PEM", "CERTIFICATE_PEM", "CERTIFICATE_DER", "PKCS7"]);
    expect(
      formatsOf(
        getExportFormatOptions(["CERTIFICATE_PEM", "PKCS12"], {
          withoutPrivateKey: true,
        }),
      ),
    ).toEqual(["CERTIFICATE_PEM"]);
  });

  it("preselects the first offered format", () => {
    expect(
      getDefaultExportFormValues(getExportFormatOptions(["PKCS12"])),
    ).toMatchObject({ format: "PKCS12", password: "" });
    expect(getDefaultExportFormValues([]).format).toBe("FULLCHAIN_PEM");
  });
});

describe("certificate export availability", () => {
  it("parses a valid block and tolerates a bad reason", () => {
    expect(
      parseCertificateExportAvailability({
        available: false,
        reason: "UNKNOWN",
        formats: "nope",
      }),
    ).toEqual({ available: false, reason: null, formats: [] });
  });

  it.each([[undefined], [null], [{}], [{ available: "yes" }]])(
    "treats %p as absent",
    (value) => {
      expect(parseCertificateExportAvailability(value)).toBeUndefined();
    },
  );

  it("is available only with a format to offer", () => {
    expect(
      isCertificateExportAvailable({
        available: true,
        reason: null,
        formats: ["PKCS12"],
      }),
    ).toBe(true);
    expect(
      isCertificateExportAvailable({
        available: true,
        reason: null,
        formats: [],
      }),
    ).toBe(false);
    expect(
      isCertificateExportAvailable({
        available: false,
        reason: "EXPIRED",
        formats: ["PKCS12"],
      }),
    ).toBe(false);
    expect(isCertificateExportAvailable(undefined)).toBe(false);
  });

  it("normalizes the detail DTO's block and drops unknown formats", () => {
    const details: SSLCertificateDetails = {
      domain: "example.com",
      status: "ACTIVE",
    };
    expect(
      withExportAvailability({
        ...details,
        export: {
          available: true,
          reason: null,
          formats: ["FULLCHAIN_PEM", "DER" as never],
        },
      }).export,
    ).toEqual({ available: true, reason: null, formats: ["FULLCHAIN_PEM"] });
    expect(withExportAvailability(details).export).toBeUndefined();
  });

  it("reads only known reasons", () => {
    expect(parseExportUnavailableReason("NOT_ACTIVE")).toBe("NOT_ACTIVE");
    expect(parseExportUnavailableReason(7)).toBeNull();
  });
});
