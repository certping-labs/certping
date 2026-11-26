// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";

import {
  useAddCredential,
  useCredentials,
  useDeleteCredential,
  useUpdateCredential,
} from "@/hooks/credentials";
import { useAuthStore } from "@/stores/auth-store";
import { server } from "@/test/msw/server";

jest.mock("sonner", () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

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

describe("credentials hooks integration (MSW)", () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: [
          "credential:read",
          "credential:create",
          "credential:rotate",
          "credential:delete",
        ],
        authMethod: "LOCAL",
      },
      expiresAt: Date.now() + 60_000,
      isLoading: false,
      isSuperAdmin: false,
    });
  });

  afterEach(() => {
    server.resetHandlers();
  });

  it("fetches and maps DNS credentials by category", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, ({ request }) => {
        const requestUrl = new URL(request.url);
        expect(requestUrl.searchParams.get("type")).toBe("DNS");
        return HttpResponse.json({
          items: [
            {
              credentialXref: "cred-dns-1",
              provider: "CLOUDFLARE",
              type: "DNS",
              description: "Cloudflare DNS",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/cloudflare",
            },
          ],
          totalItems: 1,
        });
      }),
    );

    const { result } = renderHook(
      () => useCredentials({ category: "dns_credential" }),
      { wrapper: createWrapper() },
    );

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.data).toEqual([
      expect.objectContaining({
        credentialXref: "cred-dns-1",
        provider: "cloudflare",
        providerName: "CLOUDFLARE",
      }),
    ]);
  });

  it("fetches and maps deployment credentials and normalizes status fields", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, ({ request }) => {
        const requestUrl = new URL(request.url);
        expect(requestUrl.searchParams.get("type")).toBe("DEPLOYMENT");
        return HttpResponse.json({
          items: [
            {
              credentialXref: "cred-dep-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Akamai deployment",
              status: "PENDING_ROTATION",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2025-01-01T00:00:00.000Z",
              updatedAt: "2025-01-02T00:00:00.000Z",
            },
            {
              credentialXref: "cred-dep-2",
              provider: "F5_BIGIP",
              type: "DEPLOYMENT",
              description: "F5 deployment",
              status: "DELETED",
              secretHandle: "https://vault/secrets/f5",
              createdAt: "2025-01-01T00:00:00.000Z",
              updatedAt: "2025-01-02T00:00:00.000Z",
            },
          ],
          totalItems: 2,
        });
      }),
    );

    const { result } = renderHook(
      () => useCredentials({ category: "deployment_target" }),
      { wrapper: createWrapper() },
    );

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.data).toEqual([
      expect.objectContaining({
        credentialXref: "cred-dep-1",
        provider: "akamai",
        status: "PENDING_ROTATION",
      }),
      expect.objectContaining({
        credentialXref: "cred-dep-2",
        provider: "f5",
        status: "INACTIVE",
      }),
    ]);
  });

  it("does not fetch credentials when disabled or missing view permission", async () => {
    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: [],
        authMethod: "LOCAL",
      },
      expiresAt: Date.now() + 60_000,
      isLoading: false,
      isSuperAdmin: false,
    });

    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () => {
        expect(false).toBe(true);
        return HttpResponse.json({ items: [], totalItems: 0 });
      }),
    );

    const { result } = renderHook(() => useCredentials({ enabled: false }), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(result.current.fetchStatus).toBe("idle");
    });
    expect(result.current.data).toBeUndefined();
  });

  it("creates, updates and deletes credential references through hook mutations", async () => {
    server.use(
      http.post(
        `${API_BASE_URL}/api/v1/credentials/deployment`,
        async ({ request }) => {
          const payload = (await request.json()) as Record<string, unknown>;
          expect(payload.provider).toBe("AKAMAI_CPS");
          return HttpResponse.json({
            credentialXref: "cred-dep-1",
            provider: "AKAMAI_CPS",
            type: "DEPLOYMENT",
            description: "Akamai deployment",
            status: "ACTIVE",
            secretHandle: "https://vault/secrets/akamai",
          });
        },
      ),
      http.put(
        `${API_BASE_URL}/api/v1/credentials/:xref`,
        async ({ request }) => {
          const payload = (await request.json()) as Record<string, unknown>;
          expect(payload.secretHandle).toBe("https://vault/secrets/f5");
          return HttpResponse.json({
            credentialXref: "cred-dep-1",
            provider: "F5_BIGIP",
            type: "DEPLOYMENT",
            status: "ACTIVE",
            updatedAt: "2026-07-22T10:00:00Z",
            message: "Credential updated",
          });
        },
      ),
      http.delete(`${API_BASE_URL}/api/v1/credentials/:xref`, () =>
        HttpResponse.json({
          credentialXref: "cred-dep-1",
          status: "DELETED",
          deletedAt: "2026-07-22T10:01:00Z",
          message: "Deleted",
        }),
      ),
    );

    const addHook = renderHook(() => useAddCredential(), {
      wrapper: createWrapper(),
    });
    const updateHook = renderHook(() => useUpdateCredential(), {
      wrapper: createWrapper(),
    });
    const deleteHook = renderHook(() => useDeleteCredential(), {
      wrapper: createWrapper(),
    });

    const created = await addHook.result.current.mutateAsync({
      type: "DEPLOYMENT",
      provider: "AKAMAI_CPS",
      description: "Akamai deployment",
      secretHandle: "https://vault/secrets/akamai",
    });
    expect(created.providerKey).toBe("akamai");

    const updated = await updateHook.result.current.mutateAsync({
      credentialXref: "cred-dep-1",
      secretHandle: "https://vault/secrets/f5",
    });
    expect(updated.message).toBe("Credential updated");

    const deleted = await deleteHook.result.current.mutateAsync("cred-dep-1");
    expect(deleted.message).toBe("Deleted");
  });

  it("creates DNS credential references through hook mutations", async () => {
    server.use(
      http.post(
        `${API_BASE_URL}/api/v1/credentials/dns`,
        async ({ request }) => {
          const payload = (await request.json()) as Record<string, unknown>;
          expect(payload.provider).toBe("CLOUDFLARE");
          return HttpResponse.json({
            credentialXref: "cred-dns-2",
            provider: "CLOUDFLARE",
            type: "DNS",
            description: "Cloudflare DNS",
            status: "ACTIVE",
            secretHandle: "https://vault/secrets/cloudflare",
          });
        },
      ),
    );

    const addHook = renderHook(() => useAddCredential(), {
      wrapper: createWrapper(),
    });

    const created = await addHook.result.current.mutateAsync({
      type: "DNS",
      provider: "CLOUDFLARE",
      description: "Cloudflare DNS",
      secretHandle: "https://vault/secrets/cloudflare",
    });

    expect(created.providerKey).toBe("cloudflare");
  });

  it("fails credential creation when user lacks create permission", async () => {
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

    const addHook = renderHook(() => useAddCredential(), {
      wrapper: createWrapper(),
    });

    await expect(
      addHook.result.current.mutateAsync({
        type: "DNS",
        provider: "CLOUDFLARE",
        description: "Cloudflare DNS",
        secretHandle: "https://vault/secrets/cloudflare",
      }),
    ).rejects.toThrow("You do not have permission to create credentials");
  });
});
