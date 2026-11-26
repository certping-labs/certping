// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect, useMemo } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";

import {
  DISCOVERED_CERTS_QUERY_KEY,
  useCanQueryDiscovery,
} from "@/hooks/discovery";
import { listDiscoveredCerts } from "@/lib/backend/discovery";
import { waitForProgressivePageWindow } from "@/lib/progressive-pagination";
import {
  DISCOVERED_CERTS_PAGE_SIZE,
  type DiscoveryFilters,
} from "@/types/discovery";

interface ProgressiveDiscoveredCertOptions {
  readonly enabled?: boolean;
}

/** Reveals the first discovery page immediately, then loads later pages in order. */
export function useProgressiveDiscoveredCerts(
  filters: DiscoveryFilters = {},
  options: ProgressiveDiscoveredCertOptions = {},
) {
  const canQuery = useCanQueryDiscovery();
  const isEnabled = options.enabled !== false && canQuery;
  const pageSize = filters.size ?? DISCOVERED_CERTS_PAGE_SIZE;
  const query = useInfiniteQuery({
    queryKey: [...DISCOVERED_CERTS_QUERY_KEY, "progressive", filters],
    enabled: isEnabled,
    initialPageParam: 0,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async ({ pageParam, signal }) => {
      if (pageParam > 0) {
        await waitForProgressivePageWindow(signal);
      }
      return listDiscoveredCerts(
        { ...filters, page: pageParam, size: pageSize },
        signal,
      );
    },
    getNextPageParam: (lastPage) => {
      const nextPage = lastPage.number + 1;
      return nextPage < lastPage.totalPages ? nextPage : undefined;
    },
  });
  const {
    fetchNextPage,
    hasNextPage,
    isFetchNextPageError,
    isFetchingNextPage,
  } = query;
  const pages = query.data?.pages;

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

  const certificates = useMemo(
    () => pages?.flatMap((page) => page.content) ?? [],
    [pages],
  );
  const firstPage = pages?.[0];
  const isInventoryComplete = Boolean(pages && !hasNextPage);

  return {
    ...query,
    data: query.data ? certificates : undefined,
    isInventoryComplete,
    isLoadingAdditionalPages:
      Boolean(pages) && !isInventoryComplete && !isFetchNextPageError,
    loadedItems: certificates.length,
    loadedPages: pages?.length ?? 0,
    totalItems: firstPage?.totalElements ?? 0,
    totalPages: firstPage?.totalPages ?? 0,
    retryAdditionalPages: fetchNextPage,
  };
}
