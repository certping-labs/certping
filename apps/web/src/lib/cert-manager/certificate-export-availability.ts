// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import {
  CERTIFICATE_EXPORT_FORMATS,
  EXPORT_UNAVAILABLE_REASONS,
  type CertificateExportAvailability,
  type CertificateExportFormat,
} from "@/types/certificate-export";
import type { SSLCertificateDetails } from "@/types/ssl";

const formatSchema = z.enum(CERTIFICATE_EXPORT_FORMATS);
const reasonSchema = z.enum(EXPORT_UNAVAILABLE_REASONS);

const availabilitySchema = z.object({
  available: z.boolean(),
  reason: reasonSchema.nullable().catch(null),
  formats: z.array(z.unknown()).catch([]),
});

const isKnownFormat = (value: unknown): value is CertificateExportFormat =>
  formatSchema.safeParse(value).success;

/**
 * Normalizes the detail DTO's `export` block. A missing or malformed block, an
 * older backend for instance, yields undefined so the certificate reads as not
 * downloadable; unknown formats are dropped rather than offered.
 */
export function parseCertificateExportAvailability(
  value: unknown,
): CertificateExportAvailability | undefined {
  const parsed = availabilitySchema.safeParse(value);
  if (!parsed.success) {
    return undefined;
  }
  return {
    available: parsed.data.available,
    reason: parsed.data.reason,
    formats: parsed.data.formats.filter(isKnownFormat),
  };
}

/** Replaces the detail DTO's raw `export` block with its normalized form. */
export function withExportAvailability(
  details: SSLCertificateDetails,
): SSLCertificateDetails {
  return {
    ...details,
    export: parseCertificateExportAvailability(details.export),
  };
}

/** True only when the backend says the files can be exported in some format. */
export function isCertificateExportAvailable(
  availability: CertificateExportAvailability | undefined,
): availability is CertificateExportAvailability {
  return Boolean(availability?.available && availability.formats.length > 0);
}

/** Reads an unknown export reason from an error body; null when it is not one. */
export function parseExportUnavailableReason(
  value: unknown,
): CertificateExportAvailability["reason"] {
  const parsed = reasonSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}
