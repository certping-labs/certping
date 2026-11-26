// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { apiClient, apiRoutes } from "@/lib/api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { getErrorMessage } from "@/lib/utils";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { useIsOrgFeatureEnabled } from "@/hooks/use-feature-flags";

// ─── Types ────────────────────────────────────────────────────────────────────

export type AgentOverallStatus = "HEALTHY" | "UNHEALTHY" | "UNKNOWN";

export interface AgentHealth {
  organizationId: number;
  overallStatus: AgentOverallStatus;
  /** null when no heartbeat has ever been received */
  listening: boolean | null;
  /** null when no heartbeat has ever been received */
  checkedAt: string | null;
  stale: boolean;
  failureReason: string | null;
}

export interface AgentHealthCadence {
  heartbeatCadenceMinutes: number;
}

// ─── Query keys ───────────────────────────────────────────────────────────────

const AGENT_HEALTH_KEY = "agent-health";
const AGENT_HEALTH_CADENCE_KEY = "agent-health-cadence";

// ─── API functions ────────────────────────────────────────────────────────────

export const getAgentHealth = async (): Promise<AgentHealth> => {
  const response = await apiClient.get<AgentHealth>(
    apiRoutes.query.agent.health,
  );
  return response.data;
};

export const getAgentHealthCadence = async (): Promise<AgentHealthCadence> => {
  const response = await apiClient.get<AgentHealthCadence>(
    apiRoutes.query.agent.healthCadence,
  );
  return response.data;
};

export const putAgentHealthCadence = async (
  heartbeatCadenceMinutes: number,
): Promise<AgentHealthCadence> => {
  const response = await apiClient.put<AgentHealthCadence>(
    apiRoutes.mutation.agent.updateHealthCadence,
    { heartbeatCadenceMinutes },
  );
  return response.data;
};

// ─── Hooks ────────────────────────────────────────────────────────────────────

/** Keeps the visible agent-health indicator fresh without background traffic. */
export const useAgentHealth = (options: { enabled?: boolean } = {}) => {
  const { enabled = true } = options;
  const isFeatureOn = useIsOrgFeatureEnabled(
    FEATURE_FLAGS.AGENT_HEALTH_MONITORING,
  );

  return useQuery({
    queryKey: [AGENT_HEALTH_KEY],
    queryFn: getAgentHealth,
    enabled: enabled && isFeatureOn,
    retry: false,
    refetchOnWindowFocus: true,
    refetchInterval: (query) =>
      query.state.error ||
      (typeof document !== "undefined" && document.visibilityState === "hidden")
        ? false
        : 30_000,
    refetchIntervalInBackground: false,
    staleTime: 15_000,
  });
};

export const useAgentHealthCadence = (options: { enabled?: boolean } = {}) => {
  const { enabled = true } = options;
  const isFeatureOn = useIsOrgFeatureEnabled(
    FEATURE_FLAGS.AGENT_HEALTH_MONITORING,
  );

  return useQuery({
    queryKey: [AGENT_HEALTH_CADENCE_KEY],
    queryFn: getAgentHealthCadence,
    enabled: enabled && isFeatureOn,
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  });
};

export const useUpdateAgentHealthCadence = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationKey: ["update-agent-health-cadence"],
    mutationFn: (heartbeatCadenceMinutes: number) =>
      putAgentHealthCadence(heartbeatCadenceMinutes),
    onMutate: () => {
      toast.loading("Updating heartbeat cadence...", {
        id: "update-agent-health-cadence",
      });
    },
    onSuccess: async (data) => {
      await queryClient.invalidateQueries({
        queryKey: [AGENT_HEALTH_CADENCE_KEY],
      });
      toast.success(
        `Heartbeat cadence updated to ${data.heartbeatCadenceMinutes} minutes`,
        { id: "update-agent-health-cadence" },
      );
    },
    onError: (error) => {
      toast.error(
        getErrorMessage(error, "Failed to update heartbeat cadence"),
        { id: "update-agent-health-cadence", duration: 6000 },
      );
    },
    onSettled: () => {
      toast.dismiss("update-agent-health-cadence");
    },
  });
};
