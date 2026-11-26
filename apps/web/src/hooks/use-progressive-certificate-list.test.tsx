// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import {
  CERTIFICATE_PAGE_REQUEST_GAP_MS,
  useProgressiveCertificateList,
} from "@/hooks/use-progressive-certificate-list";

const listCertificatesPageMock = jest.fn();
const getCertificateByXrefMock = jest.fn();

jest.mock("@/lib/backend/certs", () => ({
  getCertificateByXref: (...args: unknown[]) =>
    getCertificateByXrefMock(...args),
  listAllCertificates: jest.fn(),
  listCertificatesPage: (...args: unknown[]) =>
    listCertificatesPageMock(...args),
}));

const createCertificate = (certificateXref: string) => ({
  certificateXref,
  domain: `${certificateXref}.example.com`,
  status: "ACTIVE",
  rawStatus: "ACTIVE",
});

const createPage = (page: number, totalPages: number) => ({
  items: [createCertificate(`cert-${page}`)],
  page,
  size: 100,
  totalItems: totalPages,
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

describe("useProgressiveCertificateList", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    listCertificatesPageMock.mockReset();
    getCertificateByXrefMock.mockReset();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("reveals page zero before requesting the remaining inventory", async () => {
    listCertificatesPageMock.mockImplementation(({ page }: { page: number }) =>
      Promise.resolve(createPage(page, 2)),
    );

    const inventory = renderHook(() => useProgressiveCertificateList(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(inventory.result.current.data).toHaveLength(1);
    });
    expect(inventory.result.current.loadedItems).toBe(1);
    expect(inventory.result.current.totalItems).toBe(2);
    expect(inventory.result.current.isInventoryComplete).toBe(false);
    expect(listCertificatesPageMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      await jest.advanceTimersByTimeAsync(CERTIFICATE_PAGE_REQUEST_GAP_MS - 1);
    });
    expect(listCertificatesPageMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      await jest.advanceTimersByTimeAsync(1);
    });
    await waitFor(() => {
      expect(inventory.result.current.data).toHaveLength(2);
    });
    expect(inventory.result.current.isInventoryComplete).toBe(true);
    expect(listCertificatesPageMock).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ page: 1, size: 100 }),
    );
  });

  it("keeps partial data available and retries only the failed next page", async () => {
    listCertificatesPageMock
      .mockResolvedValueOnce(createPage(0, 2))
      .mockRejectedValueOnce(new Error("database temporarily unavailable"))
      .mockResolvedValueOnce(createPage(1, 2));

    const inventory = renderHook(() => useProgressiveCertificateList(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => expect(inventory.result.current.data).toHaveLength(1));
    await act(async () => {
      await jest.advanceTimersByTimeAsync(CERTIFICATE_PAGE_REQUEST_GAP_MS);
    });
    await waitFor(() => {
      expect(inventory.result.current.isFetchNextPageError).toBe(true);
    });
    expect(inventory.result.current.data).toHaveLength(1);
    expect(listCertificatesPageMock).toHaveBeenCalledTimes(2);

    act(() => {
      void inventory.result.current.retryAdditionalPages();
    });
    await act(async () => {
      await jest.advanceTimersByTimeAsync(CERTIFICATE_PAGE_REQUEST_GAP_MS);
    });
    await waitFor(() => expect(inventory.result.current.data).toHaveLength(2));
    expect(inventory.result.current.isInventoryComplete).toBe(true);
    expect(listCertificatesPageMock).toHaveBeenCalledTimes(3);
  });

  it("cancels the paced follow-up when the page unmounts", async () => {
    listCertificatesPageMock.mockImplementation(({ page }: { page: number }) =>
      Promise.resolve(createPage(page, 2)),
    );

    const inventory = renderHook(() => useProgressiveCertificateList(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => expect(inventory.result.current.data).toHaveLength(1));
    inventory.unmount();
    await act(async () => {
      await jest.advanceTimersByTimeAsync(CERTIFICATE_PAGE_REQUEST_GAP_MS);
    });

    expect(listCertificatesPageMock).toHaveBeenCalledTimes(1);
  });

  it("completes immediately when the backend has one page", async () => {
    listCertificatesPageMock.mockResolvedValue(createPage(0, 1));

    const inventory = renderHook(() => useProgressiveCertificateList(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(inventory.result.current.isInventoryComplete).toBe(true);
    });
    expect(inventory.result.current.loadedPages).toBe(1);
    expect(inventory.result.current.totalPages).toBe(1);
    expect(listCertificatesPageMock).toHaveBeenCalledTimes(1);
  });

  it("does not request inventory while disabled", async () => {
    const inventory = renderHook(
      () => useProgressiveCertificateList({ enabled: false }),
      { wrapper: createWrapper() },
    );

    await act(async () => {
      await Promise.resolve();
    });

    expect(inventory.result.current.data).toBeUndefined();
    expect(inventory.result.current.loadedItems).toBe(0);
    expect(listCertificatesPageMock).not.toHaveBeenCalled();
  });
});
