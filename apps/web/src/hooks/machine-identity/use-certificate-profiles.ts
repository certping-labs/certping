// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  archiveCertificateProfile,
  createCertificateProfile,
  getCertificateProfile,
  listCertificateProfileEvents,
  listCertificateProfiles,
  syncSourceProfiles,
  updateCertificateProfile,
} from "@/lib/backend/machine-identity/profiles";
import { isConflictError } from "@/lib/http-errors";
import { getErrorMessage } from "@/lib/utils";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import {
  adaptiveRefetchInterval,
  ambientRefetchInterval,
  POLLED_QUERY_OPTIONS,
} from "@/lib/machine-identity/polling";
import { useAuthStore } from "@/stores/auth-store";
import type {
  CertificateProfilePage,
  CertificateProfileResponse,
  CreateCertificateProfileRequest,
  ProfileListParams,
  UpdateCertificateProfileRequest,
} from "@/types/machine-identity-backend";
import type { PageRequestParams } from "@/types/pagination";
import { machineIdentityKeys } from "./query-keys";
import { useIsProfileManagementOn } from "@/hooks/machine-identity/use-machine-identity-access";

interface QueryOptions {
  enabled?: boolean;
}

/**
 * A profile push is asynchronous: CertPing stores the desired state, marks it
 * `PENDING`, and the agent applies it against the provider and reports back.
 * Until that lands the page is showing an intention, not a fact, so it is
 * worth watching closely - and only then.
 */
const isProfilePending = (
  profile: CertificateProfileResponse | undefined,
): boolean => profile?.providerSyncStatus === "PENDING";

const hasPendingProfile = (page: CertificateProfilePage | undefined): boolean =>
  (page?.content ?? []).some(
    (profile) => profile.providerSyncStatus === "PENDING",
  );

export function useCertificateProfiles(
  params: ProfileListParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsProfileManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.profileList(user?.organizationId, params),
    queryFn: () => listCertificateProfiles(params),
    enabled: isFeatureOn && options.enabled !== false,
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    refetchInterval: (query) =>
      adaptiveRefetchInterval(
        query,
        hasPendingProfile,
        MACHINE_IDENTITY_CONFIG.polling.ambientMs,
      ),
  });
}

/**
 * How many profiles match `params`, from the server's `totalElements`. Same
 * one-row count as {@link useCertificateCount}: exact regardless of fleet size,
 * and it does not pull a page of rows nothing renders.
 */
export function useCertificateProfileCount(
  params: ProfileListParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const countParams: ProfileListParams = { ...params, page: 0, size: 1 };
  const isFeatureOn = useIsProfileManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.profileList(
      user?.organizationId,
      countParams,
    ),
    queryFn: () => listCertificateProfiles(countParams),
    select: (page) => page.totalElements,
    enabled: isFeatureOn && options.enabled !== false,
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    refetchInterval: ambientRefetchInterval,
  });
}

export function useCertificateProfile(
  profileXref: string | undefined,
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsProfileManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.profile(user?.organizationId, profileXref),
    queryFn: () => getCertificateProfile(profileXref as string),
    enabled: isFeatureOn && options.enabled !== false && Boolean(profileXref),
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.detail.staleTimeMs,
    refetchInterval: (query) =>
      adaptiveRefetchInterval(
        query,
        isProfilePending,
        MACHINE_IDENTITY_CONFIG.polling.ambientMs,
      ),
  });
}

export function useCertificateProfileEvents(
  profileXref: string | undefined,
  params: PageRequestParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsProfileManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.profileEventList(
      user?.organizationId,
      profileXref,
      params,
    ),
    queryFn: () => listCertificateProfileEvents(profileXref as string, params),
    enabled: isFeatureOn && options.enabled !== false && Boolean(profileXref),
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    refetchInterval: ambientRefetchInterval,
  });
}

export function useCreateCertificateProfile() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (input: CreateCertificateProfileRequest) =>
      createCertificateProfile(input),
    onSuccess: async (profile) => {
      toast.success(
        profile.lifecycleStatus === "DRAFT"
          ? `Profile "${profile.name}" saved as draft`
          : `Profile "${profile.name}" created and dispatched to the source`,
      );
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.profiles(user?.organizationId),
      });
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, "The profile could not be created"));
    },
  });
}

export function useUpdateCertificateProfile() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: ({
      profileXref,
      input,
    }: {
      profileXref: string;
      input: UpdateCertificateProfileRequest;
    }) => updateCertificateProfile(profileXref, input),
    onSuccess: async (profile) => {
      toast.success(`Profile "${profile.name}" updated`);
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.profiles(user?.organizationId),
      });
    },
    onError: (error) => {
      if (isConflictError(error)) {
        toast.error(
          "This profile changed since you loaded it. Reload and try again.",
        );
        return;
      }
      toast.error(getErrorMessage(error, "The profile could not be updated"));
    },
  });
}

/**
 * Archives a profile a completed discovery proved is gone from the provider.
 *
 * <p>Only reachable from `providerSyncStatus: "NOT_FOUND"`; the backend
 * answers `409` from any other state, which is worth saying plainly - the
 * operator's next step is to run discovery, not to retry the delete.
 */
export function useArchiveCertificateProfile() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (profileXref: string) => archiveCertificateProfile(profileXref),
    onSuccess: async () => {
      toast.success("Profile archived");
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.profiles(user?.organizationId),
      });
    },
    onError: (error) => {
      if (isConflictError(error)) {
        toast.error(
          "Run a discovery first. A profile can only be archived once the provider has confirmed it is gone.",
        );
        return;
      }
      toast.error(getErrorMessage(error, "The profile could not be archived"));
    },
  });
}

/** Requests provider-side discovery of native profiles for a source. */
export function useSyncSourceProfiles() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (sourceXref: string) => syncSourceProfiles(sourceXref),
    onSuccess: async () => {
      toast.success("Profile discovery started");
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.profiles(user?.organizationId),
      });
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, "Discovery could not be started"));
    },
  });
}
