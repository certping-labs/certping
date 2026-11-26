// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: { get: jest.fn(), post: jest.fn(), delete: jest.fn() },
  };
});
jest.mock("@/lib/backend/deployment-info", () => ({
  getDeploymentInfo: jest.fn(),
}));

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";

import {
  useAgentTokens,
  useCreateAgentToken,
  useRevokeAgentToken,
} from "@/hooks/agent-tokens";
import { useAgentTransport } from "@/hooks/use-deployment-mode";
import { apiClient, apiRoutes } from "@/lib/api";
import { getDeploymentInfo } from "@/lib/backend/deployment-info";

const client = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
  delete: jest.Mock;
};

function wrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

describe("agent token hooks", () => {
  beforeEach(() => jest.clearAllMocks());

  it("lists the organization's tokens", async () => {
    client.get.mockResolvedValue({ data: [{ id: 1, name: "a" }] });
    const { result } = renderHook(() => useAgentTokens(7, { enabled: true }), {
      wrapper: wrapper(),
    });
    await waitFor(() => expect(result.current.data).toHaveLength(1));
    expect(client.get).toHaveBeenCalledWith(apiRoutes.query.agent.tokens, {
      params: { organizationId: "7" },
    });
  });

  it("lists the caller's own organization when no id is given", async () => {
    client.get.mockResolvedValue({ data: [] });
    renderHook(() => useAgentTokens(undefined, { enabled: true }), {
      wrapper: wrapper(),
    });
    await waitFor(() =>
      expect(client.get).toHaveBeenCalledWith(apiRoutes.query.agent.tokens, {
        params: undefined,
      }),
    );
  });

  it("creates and revokes tokens", async () => {
    client.post.mockResolvedValue({ data: { value: "cpa_x" } });
    client.delete.mockResolvedValue({ data: undefined });
    const create = renderHook(() => useCreateAgentToken("7"), {
      wrapper: wrapper(),
    });
    await expect(
      create.result.current.mutateAsync({
        name: "edge",
        serverUrl: "https://c.example",
      }),
    ).resolves.toEqual({ value: "cpa_x" });
    expect(client.post).toHaveBeenCalledWith(
      apiRoutes.query.agent.tokens,
      { name: "edge", serverUrl: "https://c.example" },
      { params: { organizationId: "7" } },
    );

    const revoke = renderHook(() => useRevokeAgentToken("7"), {
      wrapper: wrapper(),
    });
    await revoke.result.current.mutateAsync(3);
    expect(client.delete).toHaveBeenCalledWith(
      apiRoutes.query.agent.tokenById(3),
      { params: { organizationId: "7" } },
    );
  });
});

describe("useAgentTransport", () => {
  const info = getDeploymentInfo as jest.Mock;

  it("reports the backend's transport, and the gateway when the field is absent", async () => {
    info.mockResolvedValueOnce({ agentTransport: "GATEWAY" });
    const gateway = renderHook(() => useAgentTransport(), {
      wrapper: wrapper(),
    });
    expect(gateway.result.current).toBeUndefined();
    await waitFor(() => expect(gateway.result.current).toBe("GATEWAY"));

    info.mockResolvedValueOnce({});
    const older = renderHook(() => useAgentTransport(), { wrapper: wrapper() });
    await waitFor(() => expect(older.result.current).toBe("GATEWAY"));
  });
});
