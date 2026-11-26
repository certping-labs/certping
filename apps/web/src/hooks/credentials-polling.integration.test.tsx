// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import { useCredentials } from "@/hooks/credentials";
import { useAuthStore } from "@/stores/auth-store";

const listCredentialReferencesMock = jest.fn();

jest.mock("@/lib/backend/credentials", () => ({
  listCredentialReferences: (...args: unknown[]) =>
    listCredentialReferencesMock(...args),
}));

jest.mock("sonner", () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

describe("credential polling", () => {
  beforeEach(() => {
    listCredentialReferencesMock.mockReset();
    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["credential:read"],
        authMethod: "LOCAL",
      },
      expiresAt: Date.now() + 60_000,
      isLoading: false,
      isSuperAdmin: false,
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("polls credential lists until pending rotation completes", async () => {
    jest.useFakeTimers();
    listCredentialReferencesMock
      .mockResolvedValueOnce({
        items: [
          {
            credentialXref: "cred-rotation-1",
            provider: "CLOUDFLARE",
            type: "DNS",
            description: "Rotating DNS credential",
            status: "PENDING_ROTATION",
          },
        ],
        totalItems: 1,
      })
      .mockResolvedValue({
        items: [
          {
            credentialXref: "cred-rotation-1",
            provider: "CLOUDFLARE",
            type: "DNS",
            description: "Rotating DNS credential",
            status: "ACTIVE",
          },
        ],
        totalItems: 1,
      });

    const credentials = renderHook(() => useCredentials(), {
      wrapper: createWrapper(),
    });

    await waitFor(() =>
      expect(credentials.result.current.isSuccess).toBe(true),
    );
    expect(listCredentialReferencesMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      await jest.advanceTimersByTimeAsync(5_000);
    });
    await waitFor(() =>
      expect(listCredentialReferencesMock).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      await jest.advanceTimersByTimeAsync(5_000);
    });
    expect(listCredentialReferencesMock).toHaveBeenCalledTimes(2);
  });

  it("keeps a pending credential list stable when polling is disabled", async () => {
    jest.useFakeTimers();
    listCredentialReferencesMock.mockResolvedValue({
      items: [
        {
          credentialXref: "cred-rotation-1",
          provider: "CLOUDFLARE",
          type: "DNS",
          description: "Rotating DNS credential",
          status: "PENDING_ROTATION",
        },
      ],
      totalItems: 1,
    });

    const credentials = renderHook(
      () => useCredentials({ pollWhilePending: false }),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(credentials.result.current.isSuccess).toBe(true),
    );

    await act(async () => {
      await jest.advanceTimersByTimeAsync(10_000);
    });
    expect(listCredentialReferencesMock).toHaveBeenCalledTimes(1);
  });
});
