// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  CERTIFICATE_POLL_INTERVAL_MS,
  type CertificateStatusUpdate,
  getCertificatePollingIdentifier,
  MAX_CERTIFICATE_STATUS_REQUESTS_PER_TICK,
  shouldPollCertificateStatus,
} from "@/lib/cert-manager/certificate-status-polling";
import type { SSLCertificateListItem } from "@/types/ssl";

export interface CertificatePollingState {
  readonly updates: readonly CertificateStatusUpdate[];
  readonly nextCandidateIndex: number;
  readonly consecutiveEmptyPolls: number;
}

export type FetchCertificateStatus = (
  certificate: SSLCertificateListItem,
) => Promise<CertificateStatusUpdate | undefined>;

export const INITIAL_CERTIFICATE_POLLING_STATE: CertificatePollingState = {
  updates: [],
  nextCandidateIndex: 0,
  consecutiveEmptyPolls: 0,
};

const MAX_CERTIFICATE_POLL_BACKOFF_MS = 30_000;

export function getPendingPollingCandidates(
  certificates: readonly SSLCertificateListItem[],
  updates: readonly CertificateStatusUpdate[],
): SSLCertificateListItem[] {
  const updatesByIdentifier = new Map(
    updates.map((update) => [update.pollingIdentifier, update.certificate]),
  );
  return certificates.filter((certificate) => {
    const pollingIdentifier = getCertificatePollingIdentifier(certificate);
    const latestCertificate =
      updatesByIdentifier.get(pollingIdentifier) ?? certificate;
    return shouldPollCertificateStatus(latestCertificate.status);
  });
}

export async function pollNextCertificateBatch(
  certificates: readonly SSLCertificateListItem[],
  currentState: CertificatePollingState,
  fetchCertificateStatus: FetchCertificateStatus,
): Promise<CertificatePollingState> {
  const pendingCandidates = getPendingPollingCandidates(
    certificates,
    currentState.updates,
  );
  if (pendingCandidates.length === 0) {
    return currentState;
  }

  const startIndex = currentState.nextCandidateIndex % pendingCandidates.length;
  const orderedCandidates = [
    ...pendingCandidates.slice(startIndex),
    ...pendingCandidates.slice(0, startIndex),
  ];
  const batch = orderedCandidates.slice(
    0,
    MAX_CERTIFICATE_STATUS_REQUESTS_PER_TICK,
  );
  const settledUpdates = await Promise.allSettled(
    batch.map(fetchCertificateStatus),
  );
  const updatesByIdentifier = new Map(
    currentState.updates.map((update) => [update.pollingIdentifier, update]),
  );

  settledUpdates.forEach((result) => {
    if (result.status === "fulfilled" && result.value) {
      updatesByIdentifier.set(result.value.pollingIdentifier, result.value);
    }
  });
  const successfulUpdateCount = settledUpdates.filter(
    (result) => result.status === "fulfilled" && result.value,
  ).length;

  return {
    updates: Array.from(updatesByIdentifier.values()),
    nextCandidateIndex: (startIndex + batch.length) % pendingCandidates.length,
    consecutiveEmptyPolls:
      successfulUpdateCount === 0 ? currentState.consecutiveEmptyPolls + 1 : 0,
  };
}

export function getCertificatePollingInterval(
  state: CertificatePollingState | undefined,
): number {
  return Math.min(
    CERTIFICATE_POLL_INTERVAL_MS * 2 ** (state?.consecutiveEmptyPolls ?? 0),
    MAX_CERTIFICATE_POLL_BACKOFF_MS,
  );
}
