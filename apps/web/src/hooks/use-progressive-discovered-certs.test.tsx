// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import { useProgressiveDiscoveredCerts } from "@/hooks/use-progressive-discovered-certs";
import { PROGRESSIVE_PAGE_REQUEST_GAP_MS } from "@/lib/progressive-pagination";

const listDiscoveredCertsMock = jest.fn();

jest.mock("@/lib/backend/discovery", () => ({
  listDiscoveredCerts: (...args: unknown[]) => listDiscoveredCertsMock(...args),
}));

jest.mock("@/lib/authz", () => ({
  canViewCertificates: () => true,
}));

jest.mock("@/stores/auth-store", () => ({
  useAuthStore: () => ({ user: { id: "user-1" } }),
}));

const createPage = (page: number, totalPages: number) => ({
  content: [{ id: page, domain: `cert-${page}.example.com` }],
  number: page,
  size: 100,
  totalElements: totalPages,
  totalPages,
});

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

describe("useProgressiveDiscoveredCerts", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    listDiscoveredCertsMock.mockReset();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("reveals the first page before pacing the remaining inventory", async () => {
    listDiscoveredCertsMock.mockImplementation(({ page }: { page: number }) =>
      Promise.resolve(createPage(page, 2)),
    );

    const inventory = renderHook(() => useProgressiveDiscoveredCerts(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => expect(inventory.result.current.data).toHaveLength(1));
    expect(listDiscoveredCertsMock).toHaveBeenCalledTimes(1);
    expect(inventory.result.current.isInventoryComplete).toBe(false);

    await act(async () => {
      await jest.advanceTimersByTimeAsync(PROGRESSIVE_PAGE_REQUEST_GAP_MS);
    });
    await waitFor(() => expect(inventory.result.current.data).toHaveLength(2));

    expect(inventory.result.current.isInventoryComplete).toBe(true);
    expect(listDiscoveredCertsMock).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ page: 1, size: 100 }),
      expect.any(AbortSignal),
    );
  });

  it("keeps partial results and retries only the failed page", async () => {
    listDiscoveredCertsMock
      .mockResolvedValueOnce(createPage(0, 2))
      .mockRejectedValueOnce(new Error("database busy"))
      .mockResolvedValueOnce(createPage(1, 2));

    const inventory = renderHook(() => useProgressiveDiscoveredCerts(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => expect(inventory.result.current.data).toHaveLength(1));
    await act(async () => {
      await jest.advanceTimersByTimeAsync(PROGRESSIVE_PAGE_REQUEST_GAP_MS);
    });
    await waitFor(() =>
      expect(inventory.result.current.isFetchNextPageError).toBe(true),
    );

    expect(inventory.result.current.data).toHaveLength(1);
    act(() => {
      void inventory.result.current.retryAdditionalPages();
    });
    await act(async () => {
      await jest.advanceTimersByTimeAsync(PROGRESSIVE_PAGE_REQUEST_GAP_MS);
    });
    await waitFor(() => expect(inventory.result.current.data).toHaveLength(2));
  });
});
