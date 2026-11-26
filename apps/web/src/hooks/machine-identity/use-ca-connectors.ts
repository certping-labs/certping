// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useQuery } from "@tanstack/react-query";

import {
  getCaConnector,
  listCaConnectors,
} from "@/lib/backend/machine-identity/ca-connectors";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import {
  ambientRefetchInterval,
  POLLED_QUERY_OPTIONS,
} from "@/lib/machine-identity/polling";
import { useAuthStore } from "@/stores/auth-store";
import { machineIdentityKeys } from "./query-keys";
import { useIsDeviceManagementOn } from "@/hooks/machine-identity/use-machine-identity-access";

interface QueryOptions {
  enabled?: boolean;
}

/** Every configured CA connector (EJBCA, Smallstep, ...) and its latest health, for the org. */
export function useCaConnectors(options: QueryOptions = {}) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.caConnectors(user?.organizationId),
    queryFn: () => listCaConnectors(),
    enabled: isFeatureOn && options.enabled !== false,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.overview.staleTimeMs,
    // Health is agent-pushed on its own probe schedule, so this only needs to
    // be slow enough not to matter and frequent enough to notice an outage.
    refetchInterval: ambientRefetchInterval,
  });
}

export function useCaConnector(
  connectorId: string | undefined,
  options: QueryOptions = {},
) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.caConnector(
      user?.organizationId,
      connectorId,
    ),
    queryFn: () => getCaConnector(connectorId as string),
    enabled: isFeatureOn && options.enabled !== false && Boolean(connectorId),
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.detail.staleTimeMs,
    refetchInterval: ambientRefetchInterval,
  });
}
