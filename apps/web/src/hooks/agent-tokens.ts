// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createAgentToken,
  listAgentTokens,
  revokeAgentToken,
} from "@/lib/backend/agent-tokens";

const AGENT_TOKENS_QUERY_KEY = ["agent-tokens"] as const;

const normalize = (organizationId?: string | number | null) =>
  organizationId ? String(organizationId).trim() : undefined;

export function useAgentTokens(
  organizationId?: string | number | null,
  options?: { enabled?: boolean },
) {
  const id = normalize(organizationId);
  return useQuery({
    queryKey: [...AGENT_TOKENS_QUERY_KEY, id || "self"],
    queryFn: () => listAgentTokens(id),
    enabled: options?.enabled,
    refetchOnWindowFocus: false,
  });
}

export function useCreateAgentToken(organizationId?: string | number | null) {
  const queryClient = useQueryClient();
  const id = normalize(organizationId);
  return useMutation({
    mutationFn: ({
      name,
      serverUrl,
      expiresInDays,
    }: {
      name: string;
      serverUrl: string;
      expiresInDays?: number;
    }) => createAgentToken(id, name, serverUrl, expiresInDays),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: AGENT_TOKENS_QUERY_KEY });
    },
  });
}

export function useRevokeAgentToken(organizationId?: string | number | null) {
  const queryClient = useQueryClient();
  const id = normalize(organizationId);
  return useMutation({
    mutationFn: (tokenId: number) => revokeAgentToken(id, tokenId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: AGENT_TOKENS_QUERY_KEY });
    },
  });
}
