// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import { rethrowWithDecodedBlobError } from "@/lib/backend/common";
import { toCertificateExportError } from "@/lib/cert-manager/certificate-export-errors";
import {
  buildFallbackExportFileName,
  parseContentDispositionFileName,
  type ExportFileNameSource,
} from "@/lib/cert-manager/certificate-export-file-name";
import type {
  CertificateExportFile,
  CertificateExportRequest,
} from "@/types/certificate-export";

/**
 * Longer than the client's 30 s default: the server may have to fetch and unwrap
 * the key through the agent's vault, and a cold first export has taken 100 s.
 */
export const CERTIFICATE_EXPORT_TIMEOUT_MS = 120_000;

/** Only PKCS12 takes a password; the backend ignores it otherwise, so it is never sent. */
const toRequestBody = (
  request: CertificateExportRequest,
): CertificateExportRequest =>
  request.format === "PKCS12"
    ? {
        format: request.format,
        password: request.password,
        legacyPkcs12: request.legacyPkcs12 === true,
      }
    : { format: request.format };

const readHeader = (headers: unknown, name: string): unknown => {
  const accessor = headers as { get?: unknown } | undefined;
  if (typeof accessor?.get === "function") {
    return (accessor.get as (header: string) => unknown)(name);
  }
  return (headers as Record<string, unknown> | undefined)?.[name];
};

/**
 * Downloads a certificate's files through the authenticated API client. The
 * request is a POST so the PFX password travels in the body, never a URL.
 *
 * @param certificateXref the certificate to export.
 * @param request the format, plus the password and legacy flag for PKCS12.
 * @param fileNameSource names the file when `Content-Disposition` is
 *   unreadable, e.g. when CORS does not expose it.
 * @returns the file and the name to save it under.
 * @throws CertificateExportError with a user-facing message.
 */
export async function exportCertificate(
  certificateXref: string,
  request: CertificateExportRequest,
  fileNameSource?: ExportFileNameSource,
): Promise<CertificateExportFile> {
  try {
    const response = await apiClient
      .post<Blob>(
        apiRoutes.mutation.certs.export(certificateXref),
        toRequestBody(request),
        { responseType: "blob", timeout: CERTIFICATE_EXPORT_TIMEOUT_MS },
      )
      .catch(rethrowWithDecodedBlobError);
    const fileName =
      parseContentDispositionFileName(
        readHeader(response.headers, "content-disposition"),
      ) ?? buildFallbackExportFileName(fileNameSource, request.format);
    return { blob: response.data, fileName };
  } catch (error) {
    throw toCertificateExportError(error, request.format);
  }
}
