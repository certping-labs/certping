// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

/**
 * Device sources: agent-advertised connections to Intune (or another
 * provider). There is no create/configure endpoint - a source appears once
 * its agent reports a first health message - and no single-source GET, so
 * `useDeviceSource` derives its record from the already-fetched list.
 */
import { useEffect, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  listDeviceSourceEvents,
  listDeviceSources,
  stopDeviceSourceSync,
  triggerDeviceSourceSync,
} from "@/lib/backend/machine-identity/sources";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import {
  adaptiveRefetchInterval,
  isRunWorthPolling,
  liveRefetchInterval,
  POLLED_QUERY_OPTIONS,
} from "@/lib/machine-identity/polling";
import { getErrorMessage } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth-store";
import type {
  DeviceSourceDto,
  DeviceSourceEventListParams,
  DeviceSourceSync,
} from "@/types/machine-identity-backend";
import { machineIdentityKeys } from "./query-keys";
import { useIsDeviceManagementOn } from "@/hooks/machine-identity/use-machine-identity-access";

interface QueryOptions {
  enabled?: boolean;
}

/** A sync is worth polling for only while it is running and still recent. */
function isSyncInFlight(sync: DeviceSourceSync | null): boolean {
  if (!sync || (sync.status !== "PENDING" && sync.status !== "RUNNING")) {
    return false;
  }
  return isRunWorthPolling(sync.requestedAt);
}

const hasSyncInFlight = (sources: DeviceSourceDto[] | undefined): boolean =>
  (sources ?? []).some((source) => isSyncInFlight(source.sync));

/** Identifies one sync run and where it got to, for change detection. */
const syncRunSignature = (sources: DeviceSourceDto[] | undefined): string =>
  (sources ?? [])
    .map(
      (source) =>
        `${source.sourceXref}:${source.sync?.syncXref ?? ""}:${source.sync?.status ?? ""}`,
    )
    .join("|");

const TERMINAL_SYNC_STATUSES = new Set(["OK", "PARTIAL", "FAILED"]);

const hasTerminalSync = (sources: DeviceSourceDto[] | undefined): boolean =>
  (sources ?? []).some(
    (source) =>
      source.sync !== null && TERMINAL_SYNC_STATUSES.has(source.sync.status),
  );

/**
 * All device sources advertised for the org.
 *
 * <p>Polls hard while a sync is in flight and slowly otherwise - a source's
 * health is agent-pushed, so it changes without anyone touching this app.
 *
 * <p>When a run reaches a terminal status the device inventory and the fleet
 * summary are invalidated once, rather than every screen polling those
 * endpoints on the chance that a sync landed. The sync is the event; the
 * inventory just needs to hear about it.
 */
export function useDeviceSources(options: QueryOptions = {}) {
  const { user } = useAuthStore();
  const queryClient = useQueryClient();

  const isFeatureOn = useIsDeviceManagementOn();
  const query = useQuery({
    queryKey: machineIdentityKeys.sources(user?.organizationId),
    queryFn: () => listDeviceSources(),
    enabled: isFeatureOn && options.enabled !== false,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    refetchInterval: (query) =>
      adaptiveRefetchInterval(
        query,
        hasSyncInFlight,
        MACHINE_IDENTITY_CONFIG.polling.ambientMs,
      ),
  });

  const previousSignature = useRef<string | null>(null);
  const organizationId = user?.organizationId;
  const signature = syncRunSignature(query.data);
  const settled = hasTerminalSync(query.data);

  useEffect(() => {
    const previous = previousSignature.current;
    previousSignature.current = signature;
    // Only on a real transition, and only once per run: the first observation
    // of an already-finished sync is just page load, not news.
    if (previous === null || previous === signature || !settled) return;

    void queryClient.invalidateQueries({
      queryKey: machineIdentityKeys.devices(organizationId),
    });
    void queryClient.invalidateQueries({
      queryKey: machineIdentityKeys.summary(organizationId),
    });
  }, [signature, settled, organizationId, queryClient]);

  return query;
}

/** A single source, found in the already-fetched list (no single-source GET exists). */
export function useDeviceSource(
  sourceXref: string | undefined,
  options: QueryOptions = {},
) {
  const sourcesQuery = useDeviceSources(options);
  return {
    ...sourcesQuery,
    data: sourcesQuery.data?.find(
      (candidate) => candidate.sourceXref === sourceXref,
    ),
  };
}

export function useDeviceSourceEvents(
  sourceXref: string | undefined,
  params: DeviceSourceEventListParams = {},
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.sourceEventList(
      user?.organizationId,
      sourceXref,
      params,
    ),
    queryFn: () => listDeviceSourceEvents(sourceXref as string, params),
    enabled: isFeatureOn && options.enabled !== false && Boolean(sourceXref),
    placeholderData: (previous) => previous,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.list.staleTimeMs,
    // An agent writes to this feed on every health probe and on every batch of
    // a running sync, so it is never finished changing.
    refetchInterval: liveRefetchInterval,
  });
}

export function useTriggerDeviceSourceSync() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (sourceXref: string) => triggerDeviceSourceSync(sourceXref),
    onSuccess: async () => {
      toast.success("Sync started");
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.sources(user?.organizationId),
      });
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, "The sync could not be started"));
    },
  });
}

/**
 * Stops future scheduled syncs. Never labeled "cancel" in the UI - there is
 * no endpoint to cancel a sync already in flight.
 */
export function useStopDeviceSourceSync() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return useMutation({
    retry: false,
    mutationFn: (sourceXref: string) => stopDeviceSourceSync(sourceXref),
    onSuccess: async () => {
      toast.success("Future syncs stopped");
      await queryClient.invalidateQueries({
        queryKey: machineIdentityKeys.sources(user?.organizationId),
      });
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, "This could not be updated"));
    },
  });
}
