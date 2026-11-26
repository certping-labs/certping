// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect, useMemo } from "react";
import { infiniteQueryOptions, useInfiniteQuery } from "@tanstack/react-query";

import { useCertificateStatusUpdates } from "@/hooks/use-certificate-list";
import { listCertificatesPage } from "@/lib/backend/certs";
import { toSslCertificateListItem } from "@/lib/cert-manager/certificate-list-item";
import { mergeCertificateStatusUpdates } from "@/lib/cert-manager/certificate-status-polling";
import {
  PROGRESSIVE_PAGE_REQUEST_GAP_MS,
  waitForProgressivePageWindow,
} from "@/lib/progressive-pagination";
import type { SSLCertificateListItem } from "@/types/ssl";

export const PROGRESSIVE_CERTIFICATE_LIST_QUERY_KEY = [
  "ssl-cert-list",
  "progressive",
] as const;

const CERTIFICATE_PAGE_SIZE = 100;
export const CERTIFICATE_PAGE_REQUEST_GAP_MS = PROGRESSIVE_PAGE_REQUEST_GAP_MS;

interface ProgressiveCertificatePage {
  readonly items: readonly SSLCertificateListItem[];
  readonly page: number;
  readonly size: number;
  readonly totalItems: number;
  readonly totalPages: number;
}

interface ProgressiveCertificateListOptions {
  readonly enabled?: boolean;
  readonly pollWhilePending?: boolean;
}

const fetchProgressiveCertificatePage = async ({
  pageParam,
  signal,
}: {
  readonly pageParam: number;
  readonly signal: AbortSignal;
}): Promise<ProgressiveCertificatePage> => {
  if (pageParam > 0) {
    await waitForProgressivePageWindow(signal);
  }

  const page = await listCertificatesPage({
    page: pageParam,
    size: CERTIFICATE_PAGE_SIZE,
    signal,
  });

  return {
    ...page,
    items: page.items.map(toSslCertificateListItem),
  };
};

/** Shared options let navigation prefetch exactly the first inventory page. */
export const progressiveCertificateListQueryOptions = () =>
  infiniteQueryOptions({
    queryKey: PROGRESSIVE_CERTIFICATE_LIST_QUERY_KEY,
    initialPageParam: 0,
    queryFn: fetchProgressiveCertificatePage,
    getNextPageParam: (lastPage) => {
      const nextPage = lastPage.page + 1;
      return nextPage < lastPage.totalPages ? nextPage : undefined;
    },
    retry: false,
    refetchOnWindowFocus: false,
  });

/** Reveals page zero immediately and fills the remaining inventory in order. */
export function useProgressiveCertificateList(
  options: ProgressiveCertificateListOptions = {},
) {
  const isEnabled = options.enabled !== false;
  const listQuery = useInfiniteQuery({
    ...progressiveCertificateListQueryOptions(),
    enabled: isEnabled,
  });
  const {
    fetchNextPage,
    hasNextPage,
    isFetchNextPageError,
    isFetchingNextPage,
  } = listQuery;
  const pages = listQuery.data?.pages;
  const certificates = useMemo(
    () => pages?.flatMap((page) => page.items) ?? [],
    [pages],
  );
  const isInventoryComplete = Boolean(pages && !hasNextPage);

  useEffect(() => {
    if (
      isEnabled &&
      hasNextPage &&
      !isFetchingNextPage &&
      !isFetchNextPageError
    ) {
      void fetchNextPage();
    }
  }, [
    fetchNextPage,
    hasNextPage,
    isEnabled,
    isFetchNextPageError,
    isFetchingNextPage,
  ]);

  const statusUpdates = useCertificateStatusUpdates(
    certificates,
    isEnabled && isInventoryComplete && options.pollWhilePending !== false,
  );
  const mergedCertificates = useMemo(
    () => mergeCertificateStatusUpdates(certificates, statusUpdates),
    [certificates, statusUpdates],
  );
  const firstPage = pages?.[0];

  return {
    ...listQuery,
    data: listQuery.data ? mergedCertificates : undefined,
    isInventoryComplete,
    isLoadingAdditionalPages:
      Boolean(pages) && !isInventoryComplete && !isFetchNextPageError,
    loadedItems: certificates.length,
    loadedPages: pages?.length ?? 0,
    totalItems: firstPage?.totalItems ?? 0,
    totalPages: firstPage?.totalPages ?? 0,
    retryAdditionalPages: fetchNextPage,
  };
}
