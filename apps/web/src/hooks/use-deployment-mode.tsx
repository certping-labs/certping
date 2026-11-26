// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useQuery } from "@tanstack/react-query";
import { getDeploymentInfo } from "@/lib/backend/deployment-info";
import type { AgentTransport, SsoLogin } from "@/types/deployment-info";

const DEPLOYMENT_INFO_QUERY_KEY = ["deployment-info"] as const;

/**
 * How this deployment's agents connect, from the public deployment-info. `undefined` while
 * loading.
 */
export function useAgentTransport(): AgentTransport | undefined {
  const query = useQuery({
    queryKey: DEPLOYMENT_INFO_QUERY_KEY,
    queryFn: getDeploymentInfo,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  if (!query.data) return undefined;
  return query.data.agentTransport ?? "GATEWAY";
}

/**
 * The installation's single sign-on provider for the login page: `null` when sign-in is local only,
 * `undefined` while loading (the page shows the password form either way).
 */
export function useSsoLogin(): SsoLogin | null | undefined {
  const query = useQuery({
    queryKey: DEPLOYMENT_INFO_QUERY_KEY,
    queryFn: getDeploymentInfo,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  if (!query.data) return undefined;
  return query.data.ssoLogin ?? null;
}

/** Whether the installation can send email; `true` while loading so nothing flickers away. */
export function useEmailEnabled(): boolean {
  const query = useQuery({
    queryKey: DEPLOYMENT_INFO_QUERY_KEY,
    queryFn: getDeploymentInfo,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  return query.data?.emailEnabled !== false;
}
