// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import {
  getCertificateByXref,
  listAllCertificates,
  listCertificatesPage,
} from "@/lib/backend/certs";
import { toSslCertificateListItem } from "@/lib/cert-manager/certificate-list-item";
import {
  type CertificateStatusUpdate,
  createCertificateStatusUpdate,
  getCertificatePollingIdentifier,
  getCertificatesRequiringStatusPolling,
  mergeCertificateStatusUpdates,
  selectCertificateStatusUpdate,
} from "@/lib/cert-manager/certificate-status-polling";
import {
  type CertificatePollingState,
  getCertificatePollingInterval,
  getPendingPollingCandidates,
  INITIAL_CERTIFICATE_POLLING_STATE,
  pollNextCertificateBatch,
} from "@/lib/cert-manager/certificate-status-polling-queue";
import type { SSLCertificateListItem } from "@/types/ssl";
import { getConditionalRefetchInterval } from "@/hooks/query-polling";

export const SSL_LIST_QUERY_KEY = "ssl-cert-list";
export const CERTIFICATE_STATUS_QUERY_KEY = "ssl-cert-status";

interface CertificateListQueryOptions {
  readonly enabled?: boolean;
  readonly pollWhilePending?: boolean;
}

export const fetchCertificateList = async (): Promise<
  SSLCertificateListItem[]
> => {
  const certificates = await listAllCertificates();
  return certificates.map(toSslCertificateListItem);
};

const fetchCertificateStatus = async (
  certificate: SSLCertificateListItem,
): Promise<CertificateStatusUpdate | undefined> => {
  if (certificate.certificateXref) {
    const updatedCertificate = await getCertificateByXref(
      certificate.certificateXref,
    );
    return createCertificateStatusUpdate(
      certificate,
      toSslCertificateListItem(updatedCertificate),
    );
  }

  const page = await listCertificatesPage({
    page: 0,
    size: 100,
    domain: certificate.domain,
  });
  const updatedCertificate = selectCertificateStatusUpdate(
    certificate,
    page.items,
  );
  return updatedCertificate
    ? createCertificateStatusUpdate(certificate, updatedCertificate)
    : undefined;
};

export const useCertificateStatusUpdates = (
  certificates: readonly SSLCertificateListItem[],
  isEnabled: boolean,
): readonly CertificateStatusUpdate[] => {
  const queryClient = useQueryClient();
  const certificatesToPoll = isEnabled
    ? getCertificatesRequiringStatusPolling(certificates)
    : [];
  const pollingQueryKey = [
    CERTIFICATE_STATUS_QUERY_KEY,
    certificatesToPoll.map((certificate) => [
      getCertificatePollingIdentifier(certificate),
      certificate.status,
      certificate.updatedAt ?? null,
    ]),
  ] as const;
  const statusQuery = useQuery({
    queryKey: pollingQueryKey,
    enabled: certificatesToPoll.length > 0,
    initialData: INITIAL_CERTIFICATE_POLLING_STATE,
    retry: false,
    queryFn: () =>
      pollNextCertificateBatch(
        certificatesToPoll,
        queryClient.getQueryData<CertificatePollingState>(pollingQueryKey) ??
          INITIAL_CERTIFICATE_POLLING_STATE,
        fetchCertificateStatus,
      ),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        getCertificatePollingInterval(query.state.data),
        (state) =>
          getPendingPollingCandidates(certificatesToPoll, state?.updates ?? [])
            .length > 0,
      ),
    refetchIntervalInBackground: false,
  });

  return statusQuery.data.updates;
};

/** Loads the certificate list and polls only rows in transitional states. */
export function useCertificateListQuery(
  options: CertificateListQueryOptions = {},
) {
  const isEnabled = options.enabled !== false;
  const listQuery = useQuery({
    queryKey: [SSL_LIST_QUERY_KEY],
    enabled: isEnabled,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: fetchCertificateList,
  });
  const statusUpdates = useCertificateStatusUpdates(
    listQuery.data ?? [],
    isEnabled && options.pollWhilePending !== false,
  );
  const certificates = useMemo(
    () =>
      listQuery.data
        ? mergeCertificateStatusUpdates(listQuery.data, statusUpdates)
        : undefined,
    [listQuery.data, statusUpdates],
  );

  return { ...listQuery, data: certificates };
}
