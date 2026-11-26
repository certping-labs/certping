// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import { toast } from "sonner";

import {
  createDeployment,
  getDeploymentSummary,
  getDeploymentCredentialConfig,
  getDeploymentByRequestId,
  queryUserDomainCertificateDeploymentSummaries,
  queryDeployments,
} from "@/lib/backend/deployments";
import { getApiErrorMessage } from "@/lib/backend/common";
import { getCertificateDetail } from "@/lib/backend/certs";
import { canCreateDeployments, canViewDeployments } from "@/lib/authz";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import type {
  CredentialReference,
  CreateDeploymentInput,
  DeploymentCredentialConfigLookup,
  DeploymentQueryFilters,
  DeploymentQueryResult,
  DeploymentRecord,
  DeploymentSummary,
  ManagedCertificateSummary,
  UserDomainCertificateDeploymentSummaryPage,
} from "@/types/cert-manager";
import {
  invalidateAlertQueries,
  invalidateAuditQueries,
  invalidateCertificateQueries,
  invalidateCredentialQueries,
  invalidateDeploymentQueries,
} from "./query-invalidation";
import { getConditionalRefetchInterval } from "./query-polling";
import { waitForProgressivePageWindow } from "@/lib/progressive-pagination";

export const DEPLOYMENTS_QUERY_KEY = ["deployments"] as const;
export const DEPLOYMENT_SUMMARY_QUERY_KEY = ["deployment-summary"] as const;
const CERTIFICATE_DEPLOYMENT_FEATURE_KEY = "CERTIFICATE_DEPLOYMENT";
const DEPLOYMENT_POLL_INTERVAL = 5_000;
const IN_PROGRESS_DEPLOYMENT_STATUSES = new Set([
  "PENDING",
  "IN_PROGRESS",
  "DEPLOYING",
]);

const isDeploymentInProgress = (
  deployment: Pick<DeploymentRecord, "status"> | null | undefined,
): boolean =>
  IN_PROGRESS_DEPLOYMENT_STATUSES.has(
    (deployment?.status || "").trim().toUpperCase(),
  );

const hasInProgressDeployments = (
  result: DeploymentQueryResult | undefined,
): boolean => result?.items.some(isDeploymentInProgress) ?? false;

const hasPendingDeploymentSummaries = (
  summaries: UserDomainCertificateDeploymentSummaryPage | undefined,
): boolean =>
  summaries?.items.some(
    (summary) =>
      summary.deploymentsRequested >
      summary.deploymentsSucceeded + summary.deploymentsFailed,
  ) ?? false;

function canUseCertificateDeployments(): boolean {
  return useFeatureFlagStore
    .getState()
    .isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY);
}

export function useDeployments(filters?: DeploymentQueryFilters) {
  const { user } = useAuthStore();
  const isDeploymentEnabled = useFeatureFlagStore((s) =>
    s.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  return useQuery({
    queryKey: [...DEPLOYMENTS_QUERY_KEY, filters || {}],
    enabled: isDeploymentEnabled && canViewDeployments(user),
    retry: false,
    refetchOnWindowFocus: false,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<DeploymentQueryResult> =>
      queryDeployments(filters),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        DEPLOYMENT_POLL_INTERVAL,
        hasInProgressDeployments,
      ),
  });
}

export function useAllDeployments(
  filters?: DeploymentQueryFilters,
  options?: { enabled?: boolean },
) {
  const { user } = useAuthStore();
  const isDeploymentEnabled = useFeatureFlagStore((s) =>
    s.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  const isEnabled =
    options?.enabled !== false &&
    isDeploymentEnabled &&
    canViewDeployments(user);
  const pageSize = filters?.size ?? 100;
  const query = useInfiniteQuery({
    queryKey: [...DEPLOYMENTS_QUERY_KEY, "all", filters || {}],
    enabled: isEnabled,
    initialPageParam: 0,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async ({ pageParam, signal }) => {
      if (pageParam > 0) await waitForProgressivePageWindow(signal);
      return queryDeployments(
        { ...filters, page: pageParam, size: pageSize },
        signal,
      );
    },
    getNextPageParam: (lastPage) => {
      const nextPage = (lastPage.page ?? 0) + 1;
      return nextPage < (lastPage.totalPages ?? 1) ? nextPage : undefined;
    },
    refetchInterval: ({ state }) =>
      state.data?.pages.some((page) => page.items.some(isDeploymentInProgress))
        ? DEPLOYMENT_POLL_INTERVAL
        : false,
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
  const records = useMemo(
    () => pages?.flatMap((page) => page.items) ?? [],
    [pages],
  );
  const firstPage = pages?.[0];
  const isInventoryComplete = Boolean(pages && !hasNextPage);

  return {
    ...query,
    data: query.data ? records : undefined,
    isInventoryComplete,
    isLoadingAdditionalPages:
      Boolean(pages) && !isInventoryComplete && !isFetchNextPageError,
    loadedItems: records.length,
    totalItems: firstPage?.totalItems ?? 0,
    retryAdditionalPages: fetchNextPage,
  };
}

export function useDeploymentSummary(options?: { enabled?: boolean }) {
  const { user } = useAuthStore();
  const isDeploymentEnabled = useFeatureFlagStore((state) =>
    state.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  return useQuery({
    queryKey: [...DEPLOYMENT_SUMMARY_QUERY_KEY, "aggregate"],
    enabled:
      options?.enabled !== false &&
      isDeploymentEnabled &&
      canViewDeployments(user),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<DeploymentSummary> => getDeploymentSummary(),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        DEPLOYMENT_POLL_INTERVAL,
        (summary) => (summary?.inProgress ?? 0) > 0,
      ),
  });
}

export function useUserDomainCertificateDeploymentSummaries(params?: {
  userDomainCertificateId?: string;
  domain?: string;
  page?: number;
  size?: number;
}) {
  const { user } = useAuthStore();
  const isDeploymentEnabled = useFeatureFlagStore((s) =>
    s.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  return useQuery({
    queryKey: [...DEPLOYMENT_SUMMARY_QUERY_KEY, params || {}],
    enabled: isDeploymentEnabled && canViewDeployments(user),
    retry: false,
    refetchOnWindowFocus: false,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<UserDomainCertificateDeploymentSummaryPage> =>
      queryUserDomainCertificateDeploymentSummaries(params),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        DEPLOYMENT_POLL_INTERVAL,
        hasPendingDeploymentSummaries,
      ),
  });
}

export function useAllUserDomainCertificateDeploymentSummaries(
  params?: {
    userDomainCertificateId?: string;
    domain?: string;
    size?: number;
  },
  options?: { enabled?: boolean },
) {
  const { user } = useAuthStore();
  const isDeploymentEnabled = useFeatureFlagStore((s) =>
    s.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  const isEnabled =
    options?.enabled !== false &&
    isDeploymentEnabled &&
    canViewDeployments(user);
  const pageSize = params?.size ?? 100;
  const query = useInfiniteQuery({
    queryKey: [...DEPLOYMENT_SUMMARY_QUERY_KEY, "all", params || {}],
    enabled: isEnabled,
    initialPageParam: 0,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async ({ pageParam, signal }) => {
      if (pageParam > 0) await waitForProgressivePageWindow(signal);
      return queryUserDomainCertificateDeploymentSummaries(
        { ...params, page: pageParam, size: pageSize },
        signal,
      );
    },
    getNextPageParam: (lastPage) => {
      const nextPage = lastPage.page + 1;
      return nextPage < lastPage.totalPages ? nextPage : undefined;
    },
    refetchInterval: ({ state }) =>
      state.data?.pages.some((page) => hasPendingDeploymentSummaries(page))
        ? DEPLOYMENT_POLL_INTERVAL
        : false,
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
  const summaries = useMemo(
    () => pages?.flatMap((page) => page.items) ?? [],
    [pages],
  );
  const firstPage = pages?.[0];
  const isInventoryComplete = Boolean(pages && !hasNextPage);

  return {
    ...query,
    data: query.data ? summaries : undefined,
    isInventoryComplete,
    isLoadingAdditionalPages:
      Boolean(pages) && !isInventoryComplete && !isFetchNextPageError,
    loadedItems: summaries.length,
    totalItems: firstPage?.totalItems ?? 0,
    retryAdditionalPages: fetchNextPage,
  };
}

export function useDeploymentByRequestId(requestId: string) {
  const isDeploymentEnabled = useFeatureFlagStore((s) =>
    s.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  return useQuery({
    queryKey: [...DEPLOYMENTS_QUERY_KEY, "request", requestId],
    enabled: isDeploymentEnabled && Boolean(requestId),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnMount: "always",
    queryFn: async (): Promise<DeploymentRecord | null> =>
      getDeploymentByRequestId(requestId),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        DEPLOYMENT_POLL_INTERVAL,
        isDeploymentInProgress,
      ),
  });
}

export function useDeploymentLiveCertificate(certificateXref?: string) {
  const isDeploymentEnabled = useFeatureFlagStore((s) =>
    s.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  return useQuery({
    queryKey: [...DEPLOYMENTS_QUERY_KEY, "certificate", certificateXref || ""],
    enabled: isDeploymentEnabled && Boolean(certificateXref),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<ManagedCertificateSummary> =>
      getCertificateDetail(certificateXref || ""),
  });
}

export function useDeploymentCredentialReference(credentialXref?: string) {
  const isDeploymentEnabled = useFeatureFlagStore((s) =>
    s.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  return useQuery({
    queryKey: [...DEPLOYMENTS_QUERY_KEY, "credential", credentialXref || ""],
    enabled: isDeploymentEnabled && Boolean(credentialXref),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<CredentialReference> => {
      const { getCredentialReference } =
        await import("@/lib/backend/credentials");
      return getCredentialReference(credentialXref || "");
    },
  });
}

export function useDeploymentCredentialConfig(
  certXref?: string,
  deploymentCredentialXref?: string,
) {
  const isDeploymentEnabled = useFeatureFlagStore((s) =>
    s.isEnabled(CERTIFICATE_DEPLOYMENT_FEATURE_KEY),
  );

  return useQuery({
    queryKey: [
      ...DEPLOYMENTS_QUERY_KEY,
      "credential-config",
      certXref || "",
      deploymentCredentialXref || "",
    ],
    enabled:
      isDeploymentEnabled && Boolean(certXref && deploymentCredentialXref),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<DeploymentCredentialConfigLookup> =>
      getDeploymentCredentialConfig(
        certXref || "",
        deploymentCredentialXref || "",
      ),
  });
}

export function useDeployCertificate() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (payload: CreateDeploymentInput) => {
      const { user } = useAuthStore.getState();
      if (!canUseCertificateDeployments()) {
        throw new Error(
          "Certificate deployment isn't available. Ask your CertPing administrator.",
        );
      }

      if (!canCreateDeployments(user)) {
        throw new Error("You do not have permission to create deployments");
      }

      return createDeployment(payload);
    },
    onSuccess: async (result) => {
      toast.success(`Deployment requested for ${result.domain}`);
      await Promise.all([
        invalidateDeploymentQueries(queryClient),
        invalidateCertificateQueries(queryClient),
        invalidateCredentialQueries(queryClient),
        invalidateAlertQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to request deployment"));
    },
  });
}
