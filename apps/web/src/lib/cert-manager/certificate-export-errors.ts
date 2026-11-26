// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import axios from "axios";

import { getApiErrorCode, getApiRetryAfterSeconds } from "@/lib/backend/common";
import { parseExportUnavailableReason } from "@/lib/cert-manager/certificate-export-availability";
import { errorReference, withReference } from "@/lib/correlation-id";
import type {
  CertificateExportFormat,
  ExportUnavailableReason,
} from "@/types/certificate-export";

const NOT_EXPORTABLE_MESSAGES: Record<ExportUnavailableReason, string> = {
  NOT_LETS_ENCRYPT: "This certificate's authority doesn't support download.",
  NOT_PLATFORM_STORED:
    "This certificate is kept in your own key vault, so CertPing can't download it.",
  NOT_ACTIVE: "This certificate isn't active, so it can't be downloaded.",
  EXPIRED: "This certificate has expired, so it can't be downloaded.",
  KEY_HELD_EXTERNALLY:
    "The private key for this certificate is held outside CertPing, so it can't be downloaded.",
  NO_MATERIAL: "CertPing doesn't hold the files for this certificate yet.",
  FEATURE_DISABLED:
    "Certificate download isn't available. Ask your CertPing administrator.",
};

const MESSAGES = {
  invalidRequest:
    "The download request wasn't accepted. Check the format and password, then try again.",
  forbidden: "You don't have permission to download this certificate.",
  keyNotPermitted:
    "You can download the certificate and chain, but not the private key.",
  notFound: "This certificate wasn't found in your organization.",
  notExportable: "This certificate can't be downloaded.",
  materialGone: "CertPing no longer holds the files for this certificate.",
  featureOff:
    "Certificate download isn't available. Ask your CertPing administrator.",
  rateLimited: "You've reached the download limit for now.",
  mismatch:
    "The stored certificate files don't match each other. Ask your CertPing administrator.",
  unreachable: "Couldn't reach CertPing. Check your connection and try again.",
  keyDownloadsUnavailable:
    "Downloads that include the private key are temporarily unavailable. Try again shortly.",
  certificateDownloadsUnavailable:
    "Certificate downloads are temporarily unavailable. Try again shortly.",
  fallback: "Couldn't download the certificate. Try again.",
} as const;

/** Statuses after which the certificate's export availability may have changed. */
const AVAILABILITY_CHANGING_STATUSES = new Set([404, 409, 410]);

const FEATURE_LOCKED_STATUS = 423;

/**
 * The 403 code for a private-key format requested without `certificate:deploy`;
 * the certificate and chain stay downloadable.
 */
const KEY_NOT_PERMITTED_CODE = "EXPORT_KEY_NOT_PERMITTED";

const isKeyNotPermitted = (failure: ExportFailure): boolean =>
  failure.status === 403 && failure.code === KEY_NOT_PERMITTED_CODE;

/**
 * Formats whose file carries the private key. A 503 for one of these usually
 * means only the key store is down, so the copy says which downloads paused.
 */
const PRIVATE_KEY_FORMATS: ReadonlySet<CertificateExportFormat> = new Set([
  "PRIVATE_KEY_PEM",
  "PKCS12",
]);

interface ExportFailure {
  status: number | null;
  /** The format that was requested; null when the caller did not say. */
  format: CertificateExportFormat | null;
  code: string | null;
  reason: ExportUnavailableReason | null;
  retryAfterSeconds: number | null;
  reference: string | undefined;
}

/**
 * An export failure reduced to what the UI needs. It deliberately drops the
 * Axios error, whose `config.data` holds the PFX password, so nothing that
 * keeps the error (React Query's mutation state, loggers) keeps the password.
 */
export class CertificateExportError extends Error implements ExportFailure {
  readonly status: number | null;
  readonly format: CertificateExportFormat | null;
  readonly code: string | null;
  readonly reason: ExportUnavailableReason | null;
  readonly retryAfterSeconds: number | null;
  readonly reference: string | undefined;

  constructor(failure: ExportFailure) {
    super(describeExportFailure(failure));
    this.name = "CertificateExportError";
    this.status = failure.status;
    this.format = failure.format;
    this.code = failure.code;
    this.reason = failure.reason;
    this.retryAfterSeconds = failure.retryAfterSeconds;
    this.reference = failure.reference;
  }

  /** True when the certificate list or detail should be fetched again. */
  get changesAvailability(): boolean {
    return (
      this.status !== null && AVAILABILITY_CHANGING_STATUSES.has(this.status)
    );
  }

  /** True when the feature was switched off for the organization (423). */
  get isFeatureLocked(): boolean {
    return this.status === FEATURE_LOCKED_STATUS;
  }

  /** True when the private key is held outside CertPing for this certificate. */
  get isKeyHeldExternally(): boolean {
    return this.reason === "KEY_HELD_EXTERNALLY";
  }

  /** True when the caller may download the certificate but not its private key. */
  get isKeyNotPermitted(): boolean {
    return isKeyNotPermitted(this);
  }
}

const unavailableMessage = (format: CertificateExportFormat | null): string =>
  format && PRIVATE_KEY_FORMATS.has(format)
    ? MESSAGES.keyDownloadsUnavailable
    : MESSAGES.certificateDownloadsUnavailable;

const rateLimitMessage = (retryAfterSeconds: number | null): string => {
  if (!retryAfterSeconds) {
    return `${MESSAGES.rateLimited} Try again later.`;
  }
  const minutes = Math.max(1, Math.ceil(retryAfterSeconds / 60));
  const unit = minutes === 1 ? "minute" : "minutes";
  return `${MESSAGES.rateLimited} Try again in ${minutes} ${unit}.`;
};

/** The calm, specific sentence shown for an export failure. */
export function describeExportFailure(failure: ExportFailure): string {
  switch (failure.status) {
    case null:
      return MESSAGES.unreachable;
    case 400:
      return MESSAGES.invalidRequest;
    case 403:
      return isKeyNotPermitted(failure)
        ? MESSAGES.keyNotPermitted
        : MESSAGES.forbidden;
    case 404:
      return MESSAGES.notFound;
    case 409:
      return failure.reason
        ? NOT_EXPORTABLE_MESSAGES[failure.reason]
        : MESSAGES.notExportable;
    case 410:
      return MESSAGES.materialGone;
    case FEATURE_LOCKED_STATUS:
      return MESSAGES.featureOff;
    case 429:
      return rateLimitMessage(failure.retryAfterSeconds);
    case 502:
      return withReference(MESSAGES.mismatch, failure.reference);
    case 503:
      return withReference(
        unavailableMessage(failure.format),
        failure.reference,
      );
    default:
      return withReference(MESSAGES.fallback, failure.reference);
  }
}

const readRetryAfterHeader = (headers: unknown): number | null => {
  const value = (headers as Record<string, unknown> | undefined)?.[
    "retry-after"
  ];
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds) : null;
};

const readReason = (body: unknown): ExportUnavailableReason | null => {
  const payload = body as
    { reason?: unknown; error?: { reason?: unknown } } | undefined;
  return parseExportUnavailableReason(
    payload?.reason ?? payload?.error?.reason,
  );
};

/**
 * Converts any export failure, with its blob body already decoded, into a
 * {@link CertificateExportError}.
 *
 * @param error the failure the request raised.
 * @param format the requested format, which picks the copy for a 503.
 */
export function toCertificateExportError(
  error: unknown,
  format: CertificateExportFormat | null = null,
): CertificateExportError {
  if (error instanceof CertificateExportError) {
    return error;
  }
  if (!axios.isAxiosError(error) || !error.response) {
    return new CertificateExportError({
      status: null,
      format,
      code: null,
      reason: null,
      retryAfterSeconds: null,
      reference: errorReference(error),
    });
  }
  return new CertificateExportError({
    status: error.response.status,
    format,
    code: getApiErrorCode(error),
    reason: readReason(error.response.data),
    retryAfterSeconds:
      getApiRetryAfterSeconds(error) ??
      readRetryAfterHeader(error.response.headers),
    reference: errorReference(error),
  });
}
