// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { KeyCustody } from "@/types/ssl";

/** File formats `POST /api/v1/certs/{certXref}/export` can produce. */
export const CERTIFICATE_EXPORT_FORMATS = [
  "FULLCHAIN_PEM",
  "CERTIFICATE_PEM",
  "CERTIFICATE_DER",
  "PKCS7",
  "PRIVATE_KEY_PEM",
  "PKCS12",
] as const;

export type CertificateExportFormat =
  (typeof CERTIFICATE_EXPORT_FORMATS)[number];

/** Why the backend says a certificate cannot be exported. */
export const EXPORT_UNAVAILABLE_REASONS = [
  // Older backends only; every CA the platform stores can be downloaded now.
  "NOT_LETS_ENCRYPT",
  "NOT_PLATFORM_STORED",
  "NOT_ACTIVE",
  "EXPIRED",
  "KEY_HELD_EXTERNALLY",
  "NO_MATERIAL",
  "FEATURE_DISABLED",
] as const;

export type ExportUnavailableReason =
  (typeof EXPORT_UNAVAILABLE_REASONS)[number];

/** The `export` block of the certificate detail DTO. */
export interface CertificateExportAvailability {
  available: boolean;
  reason: ExportUnavailableReason | null;
  formats: CertificateExportFormat[];
}

/** Body of an export request; the password applies to PKCS12 only. */
export interface CertificateExportRequest {
  format: CertificateExportFormat;
  password?: string;
  legacyPkcs12?: boolean;
}

/** A downloaded certificate file, ready to save. */
export interface CertificateExportFile {
  blob: Blob;
  fileName: string;
}

/** The certificate a download dialog acts on. */
export interface CertificateDownloadTarget {
  certificateXref: string;
  domain: string;
  /** Names a fallback file `_wildcard.<domain>`, as the backend would. */
  isWildcard?: boolean;
  /** Formats the backend offers; every format when the source does not say. */
  formats?: readonly CertificateExportFormat[];
  /** Who holds the private key; a customer-held key is never offered for download. */
  keyCustody?: KeyCustody;
}
