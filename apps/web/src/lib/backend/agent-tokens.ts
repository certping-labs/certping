// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";

/** An agent token as listed; the token value itself is never returned after creation. */
export interface AgentToken {
  id: number;
  organizationId: number | string;
  name: string;
  tokenPrefix: string;
  createdBy?: string | null;
  createdAt?: string | null;
  lastUsedAt?: string | null;
  revokedAt?: string | null;
  /** When the token stops working; null or absent means it never expires. */
  expiresAt?: string | null;
}

/** Choices offered for a new token's lifetime; the server accepts 1 to 3650 days. */
export const AGENT_TOKEN_EXPIRY_OPTIONS = [
  { label: "Never", days: undefined },
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "365 days", days: 365 },
] as const;

/** True when the token has an expiry that is already past. */
export const isAgentTokenExpired = (
  token: Pick<AgentToken, "expiresAt">,
  now: number = Date.now(),
): boolean => {
  if (!token.expiresAt) return false;
  const expiresAt = new Date(token.expiresAt).getTime();
  return Number.isFinite(expiresAt) && expiresAt <= now;
};

/** Returned once, when a token is created. */
export interface CreatedAgentToken {
  token: AgentToken;
  value: string;
  gatewayPath: string;
  dockerCommand: string;
}

const params = (organizationId?: string | number) =>
  organizationId ? { organizationId } : undefined;

export const listAgentTokens = async (
  organizationId?: string | number,
): Promise<AgentToken[]> => {
  const response = await apiClient.get<AgentToken[]>(
    apiRoutes.query.agent.tokens,
    { params: params(organizationId) },
  );
  return response.data;
};

export const createAgentToken = async (
  organizationId: string | number | undefined,
  name: string,
  serverUrl: string,
  expiresInDays?: number,
): Promise<CreatedAgentToken> => {
  const response = await apiClient.post<CreatedAgentToken>(
    apiRoutes.query.agent.tokens,
    // Omitted expiresInDays means the token never expires.
    expiresInDays === undefined
      ? { name, serverUrl }
      : { name, serverUrl, expiresInDays },
    { params: params(organizationId) },
  );
  return response.data;
};

export const revokeAgentToken = async (
  organizationId: string | number | undefined,
  tokenId: number,
): Promise<void> => {
  await apiClient.delete(apiRoutes.query.agent.tokenById(tokenId), {
    params: params(organizationId),
  });
};
