// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  deleteDiscoveryConfig,
  getDiscoveredCertificate,
  getDiscoveryConfigStatus,
  listAllDiscoveredCerts,
  listDiscoveryConfigs,
  rerunAllDiscoveryConfigs,
  rerunDiscoveryConfig,
  triggerDiscovery,
} from "@/lib/backend/discovery";
import { getApiErrorMessage } from "@/lib/backend/common";
import {
  isActiveDiscoveryConfigStatus,
  isTerminalDiscoveryConfigStatus,
} from "@/lib/cert-manager/discovery-status";
import {
  canViewCertificates,
  canTriggerDiscovery,
  canDeleteCertificates,
} from "@/lib/authz";
import { useAuthStore } from "@/stores/auth-store";
import { useIsOrgFeatureEnabled } from "@/hooks/use-feature-flags";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import type { DiscoveryFilters } from "@/types/discovery";
import { getConditionalRefetchInterval } from "./query-polling";

export const DISCOVERED_CERTS_QUERY_KEY = ["discovery", "certs"] as const;
export const DISCOVERED_CERT_QUERY_KEY = ["discovery", "cert"] as const;
export const DISCOVERY_CONFIG_QUERY_KEY = ["discovery", "config"] as const;

const DISCOVERY_CONFIG_POLL_INTERVAL_MS = 5_000;
const DISCOVERY_CONFIG_MAX_POLL_MS = 20 * 60 * 1_000;

function shouldPollDiscoveryConfig(startedAt: string | null): boolean {
  if (!startedAt) {
    return true;
  }

  const startedAtMs = new Date(startedAt).getTime();
  if (!Number.isFinite(startedAtMs)) {
    return true;
  }

  return Date.now() - startedAtMs <= DISCOVERY_CONFIG_MAX_POLL_MS;
}

/**
 * True when discovery reads may run: the viewer can see certificates and
 * DISCOVERY is confirmed on. While the flag is unknown or off the API answers
 * 423, so every discovery query waits on this.
 */
export function useCanQueryDiscovery(): boolean {
  const canView = useAuthStore((state) => canViewCertificates(state.user));
  const isDiscoveryOn = useIsOrgFeatureEnabled(FEATURE_FLAGS.DISCOVERY);
  return canView && isDiscoveryOn;
}

export function useDiscoveredCerts(
  filters: DiscoveryFilters = {},
  options: { enabled?: boolean } = {},
) {
  const canQuery = useCanQueryDiscovery();
  const { enabled = true } = options;

  return useQuery({
    queryKey: [...DISCOVERED_CERTS_QUERY_KEY, filters],
    enabled: enabled && canQuery,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => listAllDiscoveredCerts(filters),
  });
}

/**
 * Fetches the full detail of a single discovered certificate, including the
 * provider-specific `providerData` (rich for Kubernetes). Used by the detail view.
 */
export function useDiscoveredCertificate(
  id: number | null | undefined,
  options: { enabled?: boolean } = {},
) {
  const canQuery = useCanQueryDiscovery();
  const { enabled = true } = options;

  return useQuery({
    queryKey: [...DISCOVERED_CERT_QUERY_KEY, id ?? null],
    enabled: enabled && canQuery && id != null,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => getDiscoveredCertificate(id as number),
  });
}

/**
 * Polls the status of a single saved discovery config. Auto-refetches every few
 * seconds while the scan is running and stops once it reaches a terminal state
 * (COMPLETE / FAILED / CREDENTIAL_INVALID).
 */
export function useDiscoveryConfigStatus(
  configId: number | null | undefined,
  options: { enabled?: boolean } = {},
) {
  const canQuery = useCanQueryDiscovery();
  const { enabled = true } = options;

  return useQuery({
    queryKey: [...DISCOVERY_CONFIG_QUERY_KEY, configId ?? null],
    enabled: enabled && canQuery && configId != null,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => getDiscoveryConfigStatus(configId as number),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        DISCOVERY_CONFIG_POLL_INTERVAL_MS,
        (config) =>
          !isTerminalDiscoveryConfigStatus(config?.status) &&
          shouldPollDiscoveryConfig(config?.startedAt ?? null),
      ),
  });
}

/**
 * Lists every saved discovery config for the org, refreshed from the latest scan
 * state. Auto-refetches while any config has a scan in flight so the UI reflects
 * live progress; stops once everything is idle/terminal.
 */
export function useDiscoveryConfigs(options: { enabled?: boolean } = {}) {
  const canQuery = useCanQueryDiscovery();
  const { enabled = true } = options;

  return useQuery({
    queryKey: [...DISCOVERY_CONFIG_QUERY_KEY, "list"],
    enabled: enabled && canQuery,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => listDiscoveryConfigs(),
    refetchInterval: (query) =>
      getConditionalRefetchInterval(
        query,
        DISCOVERY_CONFIG_POLL_INTERVAL_MS,
        (configs) =>
          (configs ?? []).some(
            (config) =>
              isActiveDiscoveryConfigStatus(config.status) &&
              shouldPollDiscoveryConfig(config.startedAt),
          ),
      ),
  });
}

export interface TriggerDiscoveryInput {
  targetType: string;
  credentialXref: string;
}

export function useTriggerDiscovery() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async ({
      targetType,
      credentialXref,
    }: TriggerDiscoveryInput) => {
      const { user } = useAuthStore.getState();
      if (!canTriggerDiscovery(user)) {
        throw new Error("You do not have permission to trigger discovery");
      }
      return triggerDiscovery(targetType, credentialXref);
    },
    onSuccess: (result) => {
      toast.success(result.message || "Discovery scan dispatched to agent");
      void queryClient.invalidateQueries({
        queryKey: DISCOVERED_CERTS_QUERY_KEY,
      });
      void queryClient.invalidateQueries({
        queryKey: DISCOVERY_CONFIG_QUERY_KEY,
      });
    },
    onError: (error) => {
      toast.error(
        getApiErrorMessage(error, "Failed to trigger discovery scan"),
      );
    },
  });
}

/** Reruns a single saved discovery config by id. */
export function useRerunDiscoveryConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (configId: number) => {
      const { user } = useAuthStore.getState();
      if (!canTriggerDiscovery(user)) {
        throw new Error("You do not have permission to run discovery");
      }
      return rerunDiscoveryConfig(configId);
    },
    onSuccess: (result) => {
      toast.success(result.message || "Discovery scan dispatched to agent");
      void queryClient.invalidateQueries({
        queryKey: DISCOVERY_CONFIG_QUERY_KEY,
      });
      void queryClient.invalidateQueries({
        queryKey: DISCOVERED_CERTS_QUERY_KEY,
      });
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to run discovery scan"));
    },
  });
}

/** Reruns every saved discovery config for the organization. */
export function useRerunAllDiscoveryConfigs() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async () => {
      const { user } = useAuthStore.getState();
      if (!canTriggerDiscovery(user)) {
        throw new Error("You do not have permission to run discovery");
      }
      return rerunAllDiscoveryConfigs();
    },
    onSuccess: (results) => {
      toast.success(
        `Dispatched ${results.length} discovery scan${results.length === 1 ? "" : "s"}`,
      );
      void queryClient.invalidateQueries({
        queryKey: DISCOVERY_CONFIG_QUERY_KEY,
      });
      void queryClient.invalidateQueries({
        queryKey: DISCOVERED_CERTS_QUERY_KEY,
      });
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error, "Failed to run discovery scans"));
    },
  });
}

/** Soft-deletes a saved discovery config (inventory rows are kept). */
export function useDeleteDiscoveryConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: async (configId: number) => {
      const { user } = useAuthStore.getState();
      if (!canDeleteCertificates(user)) {
        throw new Error(
          "You do not have permission to delete discovery configs",
        );
      }
      await deleteDiscoveryConfig(configId);
    },
    onSuccess: () => {
      toast.success("Discovery configuration removed");
      void queryClient.invalidateQueries({
        queryKey: DISCOVERY_CONFIG_QUERY_KEY,
      });
    },
    onError: (error) => {
      toast.error(
        getApiErrorMessage(error, "Failed to remove discovery configuration"),
      );
    },
  });
}
