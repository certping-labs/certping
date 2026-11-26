// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import {
  CERTIFICATE_EXPORT_FORMATS,
  type CertificateExportFormat,
  type CertificateExportRequest,
} from "@/types/certificate-export";

/**
 * Printable ASCII only: Java and some Windows tooling can't open PKCS#12 files
 * protected with other characters, so the backend refuses them.
 */
const PFX_PASSWORD_PATTERN = /^[\x20-\x7E]*$/;

export const PFX_PASSWORD_CHARSET_MESSAGE =
  "Use letters, numbers and standard symbols only (no accents or emoji). Some servers can't open files protected with other characters.";

/** The backend's PKCS12 password bounds. */
export const PFX_PASSWORD_MIN_LENGTH = 8;
export const PFX_PASSWORD_MAX_LENGTH = 128;

export interface CertificateExportFormatOption {
  format: CertificateExportFormat;
  label: string;
  description: string;
  isRecommended: boolean;
  containsPrivateKey: boolean;
}

/** Offered in this order; the first one available is preselected. */
export const CERTIFICATE_EXPORT_FORMAT_OPTIONS: readonly CertificateExportFormatOption[] =
  [
    {
      format: "FULLCHAIN_PEM",
      label: "Full chain (PEM)",
      description:
        "Your certificate with its intermediates. Use this for Nginx, Apache, and most Linux servers.",
      isRecommended: true,
      containsPrivateKey: false,
    },
    {
      format: "CERTIFICATE_PEM",
      label: "Certificate only (PEM)",
      description:
        "Just your certificate, for servers that take the chain as a separate file.",
      isRecommended: false,
      containsPrivateKey: false,
    },
    {
      format: "CERTIFICATE_DER",
      label: "Binary certificate (DER)",
      description:
        "Just your certificate, in binary form, for Windows and Java key stores.",
      isRecommended: false,
      containsPrivateKey: false,
    },
    {
      format: "PKCS7",
      label: "Certificate chain (PKCS#7, .p7b)",
      description:
        "Your certificate with its intermediates in one bundle. Use this for IIS and Tomcat.",
      isRecommended: false,
      containsPrivateKey: false,
    },
    {
      format: "PRIVATE_KEY_PEM",
      label: "Private key (PEM)",
      description: "The key that pairs with the certificate, in PKCS#8 format.",
      isRecommended: false,
      containsPrivateKey: true,
    },
    {
      format: "PKCS12",
      label: "PFX / PKCS#12",
      description:
        "Certificate, chain, and key in one password-protected file. Use this for IIS, Windows, and Azure App Service.",
      isRecommended: false,
      containsPrivateKey: true,
    },
  ];

interface ExportFormatOptionFilter {
  /** Drops the formats that carry the private key, e.g. after the backend refused it. */
  withoutPrivateKey?: boolean;
}

/**
 * The options to show: the backend's offer when it gives one, else every
 * format, minus the private-key formats when asked.
 */
export function getExportFormatOptions(
  formats: readonly CertificateExportFormat[] | undefined,
  { withoutPrivateKey = false }: ExportFormatOptionFilter = {},
): readonly CertificateExportFormatOption[] {
  const offered = formats?.length ? new Set(formats) : null;
  if (offered === null && !withoutPrivateKey) {
    return CERTIFICATE_EXPORT_FORMAT_OPTIONS;
  }
  return CERTIFICATE_EXPORT_FORMAT_OPTIONS.filter(
    (option) =>
      (offered === null || offered.has(option.format)) &&
      !(withoutPrivateKey && option.containsPrivateKey),
  );
}

export const certificateExportFormSchema = z
  .object({
    format: z.enum(CERTIFICATE_EXPORT_FORMATS),
    password: z.string(),
    confirmPassword: z.string(),
    legacyPkcs12: z.boolean(),
  })
  .superRefine((values, context) => {
    if (values.format !== "PKCS12") {
      return;
    }
    if (values.password.length < PFX_PASSWORD_MIN_LENGTH) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["password"],
        message: `Use at least ${PFX_PASSWORD_MIN_LENGTH} characters.`,
      });
    } else if (values.password.length > PFX_PASSWORD_MAX_LENGTH) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["password"],
        message: `Use ${PFX_PASSWORD_MAX_LENGTH} characters or fewer.`,
      });
    } else if (!PFX_PASSWORD_PATTERN.test(values.password)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["password"],
        message: PFX_PASSWORD_CHARSET_MESSAGE,
      });
    }
    if (values.confirmPassword !== values.password) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["confirmPassword"],
        message: "The passwords don't match.",
      });
    }
  });

export type CertificateExportFormValues = z.infer<
  typeof certificateExportFormSchema
>;

export function getDefaultExportFormValues(
  options: readonly CertificateExportFormatOption[],
): CertificateExportFormValues {
  return {
    format: options[0]?.format ?? "FULLCHAIN_PEM",
    password: "",
    confirmPassword: "",
    legacyPkcs12: false,
  };
}

/** The request body for the chosen values; the password only rides with PKCS12. */
export function toCertificateExportRequest(
  values: CertificateExportFormValues,
): CertificateExportRequest {
  if (values.format !== "PKCS12") {
    return { format: values.format };
  }
  return {
    format: values.format,
    password: values.password,
    legacyPkcs12: values.legacyPkcs12,
  };
}
