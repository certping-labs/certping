// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  createIntegration,
  deleteIntegration,
  getIntegration,
  listIntegrations,
  updateIntegration,
} from "@/lib/backend/integrations";
import { getApiErrorMessage } from "@/lib/backend/common";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { useAuthStore } from "@/stores/auth-store";
import type {
  CreateIntegrationPayload,
  UpdateIntegrationPayload,
} from "@/types/integrations";

export const INTEGRATIONS_QUERY_KEY = "integrations";
const normalizeOrganizationScope = (
  organizationId: string | null | undefined,
) => organizationId?.trim() || null;

export const integrationQueryKeys = {
  all: [INTEGRATIONS_QUERY_KEY] as const,
  list: (organizationId: string | null | undefined) =>
    [
      INTEGRATIONS_QUERY_KEY,
      "list",
      normalizeOrganizationScope(organizationId),
    ] as const,
  detail: (
    organizationId: string | null | undefined,
    integrationId: number | string | undefined,
  ) =>
    [
      INTEGRATIONS_QUERY_KEY,
      "detail",
      normalizeOrganizationScope(organizationId),
      integrationId,
    ] as const,
};

const invalidateIntegrationQueries = async (
  queryClient: ReturnType<typeof useQueryClient>,
) => {
  await queryClient.invalidateQueries({
    queryKey: integrationQueryKeys.all,
  });
};

/** INTEGRATIONS gates every integrations endpoint (423 while it is off). */
const useIsIntegrationsEnabled = () =>
  useIsFeatureEnabled(FEATURE_FLAGS.INTEGRATIONS);

export const useListIntegrations = (options?: { enabled?: boolean }) => {
  const organizationId = useAuthStore(
    (state) => state.user?.organizationId ?? null,
  );
  const isFeatureOn = useIsIntegrationsEnabled();
  return useQuery({
    queryKey: integrationQueryKeys.list(organizationId),
    enabled: options?.enabled !== false && isFeatureOn,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: listIntegrations,
  });
};

export const useGetIntegration = (
  integrationId: number | string | undefined,
  options?: { enabled?: boolean },
) => {
  const organizationId = useAuthStore(
    (state) => state.user?.organizationId ?? null,
  );
  const isFeatureOn = useIsIntegrationsEnabled();
  return useQuery({
    queryKey: integrationQueryKeys.detail(organizationId, integrationId),
    enabled:
      options?.enabled !== false && integrationId !== undefined && isFeatureOn,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => getIntegration(integrationId!),
  });
};

export const useCreateIntegration = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: (payload: CreateIntegrationPayload) =>
      createIntegration(payload),
    onSuccess: async () => {
      toast.success("Integration connected");
      await invalidateIntegrationQueries(queryClient);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to connect integration"));
    },
  });
};

export const useUpdateIntegration = (integrationId: number | string) => {
  const queryClient = useQueryClient();
  const organizationId = useAuthStore(
    (state) => state.user?.organizationId ?? null,
  );

  return useMutation({
    retry: false,
    mutationFn: (payload: UpdateIntegrationPayload) =>
      updateIntegration(integrationId, payload),
    onSuccess: async () => {
      toast.success("Integration updated");
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: integrationQueryKeys.detail(organizationId, integrationId),
        }),
        invalidateIntegrationQueries(queryClient),
      ]);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to update integration"));
    },
  });
};

export const useDeleteIntegration = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: (integrationId: number | string) =>
      deleteIntegration(integrationId),
    onSuccess: async () => {
      toast.success("Integration deleted");
      await invalidateIntegrationQueries(queryClient);
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to delete integration"));
    },
  });
};
