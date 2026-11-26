// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  getAgent,
  getDeepHealthCheck,
  getDeepHealthCheckMetrics,
  isDeepHealthCheckDone,
  listAgents,
  startAgentHealthCheck,
} from "@/lib/backend/agents";

export const AGENTS_QUERY_KEY = ["agents"] as const;

export function useAgents(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: AGENTS_QUERY_KEY,
    queryFn: listAgents,
    enabled: options?.enabled ?? true,
    retry: false,
    refetchOnWindowFocus: true,
    refetchInterval: (query) => (query.state.error ? false : 30_000),
    refetchIntervalInBackground: false,
  });
}

export function useAgent(
  agentId: string | number | null | undefined,
  options?: { enabled?: boolean },
) {
  return useQuery({
    queryKey: [...AGENTS_QUERY_KEY, String(agentId ?? "")],
    queryFn: () => getAgent(agentId as string | number),
    enabled: (options?.enabled ?? true) && agentId != null && agentId !== "",
    retry: false,
    refetchOnWindowFocus: false,
  });
}

export function useStartAgentHealthCheck() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string | number) => startAgentHealthCheck(agentId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: AGENTS_QUERY_KEY });
    },
  });
}

/** Polls one deep health check until the agent has answered it, then loads its metrics. */
export function useDeepHealthCheck(deepCheckId: string, polling: boolean) {
  const check = useQuery({
    queryKey: ["agent-deep-health", deepCheckId],
    queryFn: () => getDeepHealthCheck(deepCheckId),
    enabled: polling,
    retry: false,
    refetchInterval: (query) =>
      polling && !isDeepHealthCheckDone(query.state.data?.status)
        ? 2_000
        : false,
    refetchOnWindowFocus: false,
    gcTime: 0,
  });
  const done = isDeepHealthCheckDone(check.data?.status);
  const metrics = useQuery({
    queryKey: ["agent-deep-health", deepCheckId, "metrics"],
    queryFn: () => getDeepHealthCheckMetrics(deepCheckId),
    enabled: done,
    retry: false,
    refetchOnWindowFocus: false,
    gcTime: 0,
  });
  return { check, metrics, done };
}
