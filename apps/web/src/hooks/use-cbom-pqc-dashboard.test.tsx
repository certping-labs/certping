// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import {
  cbomPqcDashboardKeys,
  useCbomDownload,
  usePqcReadinessCertificates,
  usePqcReadinessReport,
} from "@/hooks/use-cbom-pqc-dashboard";

const getCbomDocumentMock = jest.fn();
const getPqcReadinessReportMock = jest.fn();
const getPqcReadinessCertificatesMock = jest.fn();

jest.mock("@/lib/backend/cbom-pqc", () => ({
  getCbomDocument: (...args: unknown[]) => getCbomDocumentMock(...args),
  getPqcReadinessReport: (...args: unknown[]) =>
    getPqcReadinessReportMock(...args),
  getPqcReadinessCertificates: (...args: unknown[]) =>
    getPqcReadinessCertificatesMock(...args),
}));

function createQueryWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: 5 } },
  });

  function QueryWrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
  }

  return { queryClient, QueryWrapper };
}

describe("CBOM and PQC dashboard queries", () => {
  beforeEach(() => {
    getCbomDocumentMock.mockReset();
    getPqcReadinessReportMock.mockReset();
    getPqcReadinessCertificatesMock.mockReset();
  });

  it("keeps the previous inventory page while the next one loads", async () => {
    const firstPage = { content: [], number: 0, totalElements: 20 };
    const secondPage = { content: [], number: 1, totalElements: 20 };
    getPqcReadinessCertificatesMock
      .mockResolvedValueOnce(firstPage)
      .mockResolvedValueOnce(secondPage);
    const { QueryWrapper } = createQueryWrapper();
    const { result, rerender } = renderHook(
      ({ page }: { page: number }) =>
        usePqcReadinessCertificates({ page, size: 15 }),
      { wrapper: QueryWrapper, initialProps: { page: 0 } },
    );

    await waitFor(() => expect(result.current.data).toBe(firstPage));

    rerender({ page: 1 });

    expect(result.current.data).toBe(firstPage);
    await waitFor(() => expect(result.current.data).toBe(secondPage));
    expect(getPqcReadinessCertificatesMock).toHaveBeenLastCalledWith({
      page: 1,
      size: 15,
    });
  });

  it("does not fetch the CBOM until a download is requested", async () => {
    getCbomDocumentMock.mockResolvedValue({ text: "{}" });
    const { QueryWrapper } = createQueryWrapper();
    const { result } = renderHook(() => useCbomDownload(), {
      wrapper: QueryWrapper,
    });

    expect(getCbomDocumentMock).not.toHaveBeenCalled();

    await act(async () => {
      await result.current.mutateAsync();
    });

    await waitFor(() => expect(result.current.data).toEqual({ text: "{}" }));
    expect(getCbomDocumentMock).toHaveBeenCalledTimes(1);
  });

  it("does not retry a failed CBOM download", async () => {
    getCbomDocumentMock.mockRejectedValue(new Error("CBOM unavailable"));
    const { QueryWrapper } = createQueryWrapper();
    const { result } = renderHook(() => useCbomDownload(), {
      wrapper: QueryWrapper,
    });

    act(() => {
      result.current.mutate();
    });

    await waitFor(() => expect(result.current.isError).toBe(true));

    expect(getCbomDocumentMock).toHaveBeenCalledTimes(1);
  });

  it("refreshes PQC readiness only when explicitly requested", async () => {
    getPqcReadinessReportMock.mockResolvedValue({
      summary: {
        totalCertificates: 0,
        pqcCompliant: 0,
        deprecated2030: 0,
        disallowed2035: 0,
        unknown: 0,
        highHndlRisk: 0,
      },
      algorithms: [],
    });
    const { queryClient, QueryWrapper } = createQueryWrapper();
    const { result } = renderHook(() => usePqcReadinessReport(), {
      wrapper: QueryWrapper,
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(getPqcReadinessReportMock).toHaveBeenCalledTimes(1);
    expect(
      queryClient.getQueryCache().find({
        queryKey: cbomPqcDashboardKeys.pqcReadiness,
      })?.options,
    ).toEqual(
      expect.objectContaining({
        retry: false,
        refetchInterval: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
      }),
    );

    await act(async () => {
      await result.current.refetch();
    });

    expect(getPqcReadinessReportMock).toHaveBeenCalledTimes(2);
  });
});
