// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useQuery } from "@tanstack/react-query";

import { getIotSummary } from "@/lib/backend/machine-identity/summary";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import {
  liveRefetchInterval,
  POLLED_QUERY_OPTIONS,
} from "@/lib/machine-identity/polling";
import { useAuthStore } from "@/stores/auth-store";
import { machineIdentityKeys } from "./query-keys";
import { useIsDeviceManagementOn } from "@/hooks/machine-identity/use-machine-identity-access";

interface QueryOptions {
  enabled?: boolean;
}

/** Fleet-wide device/source totals for the module overview dashboard. */
export function useIotSummary(options: QueryOptions = {}) {
  const { user } = useAuthStore();
  const isFeatureOn = useIsDeviceManagementOn();
  return useQuery({
    queryKey: machineIdentityKeys.summary(user?.organizationId),
    queryFn: () => getIotSummary(),
    enabled: isFeatureOn && options.enabled !== false,
    ...POLLED_QUERY_OPTIONS,
    staleTime: MACHINE_IDENTITY_CONFIG.overview.staleTimeMs,
    // One request carries every status count and posture breakdown, and the
    // inventory tiles are read from it - so it tracks the list it sits above
    // rather than lagging a slower cadence behind it.
    refetchInterval: liveRefetchInterval,
  });
}
