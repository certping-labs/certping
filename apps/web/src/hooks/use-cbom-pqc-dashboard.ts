// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery } from "@tanstack/react-query";

import {
  getCbomDocument,
  getPqcReadinessCertificates,
  getPqcReadinessReport,
} from "@/lib/backend/cbom-pqc";
import type { PqcReadinessCertificatesParams } from "@/types/cbom-pqc";

export const cbomPqcDashboardKeys = {
  pqcReadiness: ["cert-manager", "pqc-readiness"] as const,
  pqcReadinessCertificates: (params: PqcReadinessCertificatesParams) =>
    ["cert-manager", "pqc-readiness", "certificates", params] as const,
};

const DASHBOARD_STALE_TIME_MS = 5 * 60 * 1_000;
const DASHBOARD_QUERY_OPTIONS = {
  staleTime: DASHBOARD_STALE_TIME_MS,
  retry: false,
  refetchInterval: false,
  refetchOnWindowFocus: false,
  refetchOnReconnect: false,
} as const;

/**
 * The CBOM is a full inventory export, so it is only fetched when the user
 * asks for it rather than on page load.
 */
export function useCbomDownload() {
  return useMutation({
    mutationFn: getCbomDocument,
    retry: false,
  });
}

export function usePqcReadinessReport() {
  return useQuery({
    queryKey: cbomPqcDashboardKeys.pqcReadiness,
    queryFn: getPqcReadinessReport,
    ...DASHBOARD_QUERY_OPTIONS,
  });
}

export function usePqcReadinessCertificates(
  params: PqcReadinessCertificatesParams,
) {
  return useQuery({
    queryKey: cbomPqcDashboardKeys.pqcReadinessCertificates(params),
    queryFn: () => getPqcReadinessCertificates(params),
    placeholderData: (previous) => previous,
    ...DASHBOARD_QUERY_OPTIONS,
  });
}
