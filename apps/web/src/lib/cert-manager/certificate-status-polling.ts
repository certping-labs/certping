// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { toSslCertificateListItem } from "@/lib/cert-manager/certificate-list-item";
import { isInFlightCertificateStatus } from "@/lib/cert-manager/certificate-status";
import type { ManagedCertificateSummary } from "@/types/cert-manager";
import type { SSLCertificateListItem } from "@/types/ssl";

export const CERTIFICATE_POLL_INTERVAL_MS = 5000;
export const MAX_CERTIFICATE_STATUS_REQUESTS_PER_TICK = 4;

export interface CertificateStatusUpdate {
  readonly pollingIdentifier: string;
  readonly certificate: SSLCertificateListItem;
}

export function shouldPollCertificateStatus(
  status: string | null | undefined,
): boolean {
  return isInFlightCertificateStatus(status);
}

const normalizeCertificateDomain = (
  domain: string | null | undefined,
): string => domain?.trim().toLowerCase() ?? "";

export function getCertificatePollingIdentifier(
  certificate: SSLCertificateListItem,
): string {
  if (certificate.userDomainCertId) {
    return `udc:${certificate.userDomainCertId}`;
  }
  if (certificate.certificateXref) {
    return `xref:${certificate.certificateXref}`;
  }
  return `domain:${normalizeCertificateDomain(certificate.domain)}`;
}

export function getCertificatesRequiringStatusPolling(
  certificates: readonly SSLCertificateListItem[],
): SSLCertificateListItem[] {
  return certificates.filter(
    (certificate) =>
      normalizeCertificateDomain(certificate.domain).length > 0 &&
      shouldPollCertificateStatus(certificate.status),
  );
}

export function selectCertificateStatusUpdate(
  certificate: SSLCertificateListItem,
  candidates: readonly ManagedCertificateSummary[],
): SSLCertificateListItem | undefined {
  const lifecycleMatch = certificate.userDomainCertId
    ? candidates.find(
        (candidate) =>
          candidate.userDomainCertId === certificate.userDomainCertId,
      )
    : undefined;
  const xrefMatch = certificate.certificateXref
    ? candidates.find(
        (candidate) =>
          candidate.certificateXref === certificate.certificateXref,
      )
    : undefined;
  const normalizedDomain = normalizeCertificateDomain(certificate.domain);
  const domainMatch =
    certificate.userDomainCertId ||
    certificate.certificateXref ||
    !normalizedDomain
      ? undefined
      : candidates.find(
          (candidate) =>
            normalizeCertificateDomain(candidate.domain) === normalizedDomain,
        );
  const match = lifecycleMatch ?? xrefMatch ?? domainMatch;

  return match ? toSslCertificateListItem(match) : undefined;
}

export function createCertificateStatusUpdate(
  originalCertificate: SSLCertificateListItem,
  updatedCertificate: SSLCertificateListItem,
): CertificateStatusUpdate {
  return {
    pollingIdentifier: getCertificatePollingIdentifier(originalCertificate),
    certificate: updatedCertificate,
  };
}

export function mergeCertificateStatusUpdates(
  certificates: readonly SSLCertificateListItem[],
  updates: readonly CertificateStatusUpdate[],
): SSLCertificateListItem[] {
  if (updates.length === 0) {
    return [...certificates];
  }

  const updatesByIdentifier = new Map(
    updates.map((update) => [update.pollingIdentifier, update.certificate]),
  );

  return certificates.map(
    (certificate) =>
      updatesByIdentifier.get(getCertificatePollingIdentifier(certificate)) ??
      certificate,
  );
}
