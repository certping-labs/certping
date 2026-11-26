// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { QueryClient } from "@tanstack/react-query";

import { CERTIFICATE_DETAILS_QUERY_KEY, getCertificateDetails } from "./ssl";
import { progressiveCertificateListQueryOptions } from "./use-progressive-certificate-list";

const STALE_TIME = 10 * 60 * 1000; // 10 minutes

export const prefetchSSLCertificates = (queryClient: QueryClient) => {
  void queryClient.prefetchInfiniteQuery({
    ...progressiveCertificateListQueryOptions(),
    staleTime: STALE_TIME,
  });
};

export const prefetchCertificateDetails = (
  queryClient: QueryClient,
  domain: string,
) => {
  queryClient.prefetchQuery({
    queryKey: [CERTIFICATE_DETAILS_QUERY_KEY, domain],
    queryFn: () => getCertificateDetails(domain),
    staleTime: STALE_TIME,
  });
};
