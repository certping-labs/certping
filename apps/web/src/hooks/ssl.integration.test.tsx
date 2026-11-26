// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import {
  useCompleteDnsChallenge,
  useCertificateHistories,
  useConvertCertificateToAutomated,
  useDeletePendingSSLCertificate,
  useGetCertificateDetails,
  useGetCertificateHistory,
  useGetTxtRecords,
  useIssueCertificateRequest,
  useIssueManualCertificateRequest,
  useListCertificates,
  useMarkAlertAsRead,
  useRenewCertificate,
  useRevokeCertificate,
} from "@/hooks/ssl";

const listAllCertificatesMock = jest.fn();
const listCertificatesPageMock = jest.fn();
const getCertificateByXrefMock = jest.fn();
const getCertificateDetailsRecordMock = jest.fn();
const issueCertificateMock = jest.fn();
const issueManualCertificateMock = jest.fn();
const convertToAutomatedMock = jest.fn();
const getCertificateTxtRecordsMock = jest.fn();
const validateCertificateDnsMock = jest.fn();
const renewCertificateMock = jest.fn();
const revokeCertificateMock = jest.fn();
const deleteCertificateMock = jest.fn();
const getCertificateHistoryMock = jest.fn();
const invalidateAlertQueriesMock = jest.fn();
const invalidateAuditQueriesMock = jest.fn();
const invalidateCertificateQueriesMock = jest.fn();
const invalidateDeploymentQueriesMock = jest.fn();
const apiPatchMock = jest.fn();

jest.mock("sonner", () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

jest.mock("@/lib/backend/certs", () => ({
  convertCertificateToAutomated: (...args: unknown[]) =>
    convertToAutomatedMock(...args),
  deleteCertificate: (...args: unknown[]) => deleteCertificateMock(...args),
  getCertificateDetailsRecord: (...args: unknown[]) =>
    getCertificateDetailsRecordMock(...args),
  getCertificateByXref: (...args: unknown[]) =>
    getCertificateByXrefMock(...args),
  getCertificateHistory: (...args: unknown[]) =>
    getCertificateHistoryMock(...args),
  getCertificateTxtRecords: (...args: unknown[]) =>
    getCertificateTxtRecordsMock(...args),
  issueCertificate: (...args: unknown[]) => issueCertificateMock(...args),
  issueManualCertificate: (...args: unknown[]) =>
    issueManualCertificateMock(...args),
  listAllCertificates: (...args: unknown[]) => listAllCertificatesMock(...args),
  listCertificatesPage: (...args: unknown[]) =>
    listCertificatesPageMock(...args),
  renewCertificate: (...args: unknown[]) => renewCertificateMock(...args),
  revokeCertificate: (...args: unknown[]) => revokeCertificateMock(...args),
  validateCertificateDns: (...args: unknown[]) =>
    validateCertificateDnsMock(...args),
}));

jest.mock("@/hooks/query-invalidation", () => ({
  invalidateAlertQueries: (...args: unknown[]) =>
    invalidateAlertQueriesMock(...args),
  invalidateAuditQueries: (...args: unknown[]) =>
    invalidateAuditQueriesMock(...args),
  invalidateCertificateQueries: (...args: unknown[]) =>
    invalidateCertificateQueriesMock(...args),
  invalidateCertificateDataQueries: (...args: unknown[]) =>
    invalidateCertificateQueriesMock(...args),
  invalidateDeploymentQueries: (...args: unknown[]) =>
    invalidateDeploymentQueriesMock(...args),
}));

jest.mock("@/lib/api", () => ({
  apiClient: {
    patch: (...args: unknown[]) => apiPatchMock(...args),
  },
  apiRoutes: {
    mutation: {
      ssl: {
        markAlertAsRead: (alertId: number) => `/api/alerts/${alertId}`,
      },
    },
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

describe("ssl hooks integration", () => {
  beforeEach(() => {
    listAllCertificatesMock.mockReset();
    listCertificatesPageMock.mockReset();
    listCertificatesPageMock.mockResolvedValue({
      items: [],
      page: 0,
      size: 1,
      totalItems: 0,
      totalPages: 0,
    });
    getCertificateByXrefMock.mockReset();
    getCertificateDetailsRecordMock.mockReset();
    issueCertificateMock.mockReset();
    issueManualCertificateMock.mockReset();
    convertToAutomatedMock.mockReset();
    getCertificateTxtRecordsMock.mockReset();
    validateCertificateDnsMock.mockReset();
    renewCertificateMock.mockReset();
    revokeCertificateMock.mockReset();
    deleteCertificateMock.mockReset();
    getCertificateHistoryMock.mockReset();
    apiPatchMock.mockReset();
    invalidateAlertQueriesMock.mockResolvedValue(undefined);
    invalidateAuditQueriesMock.mockResolvedValue(undefined);
    invalidateCertificateQueriesMock.mockResolvedValue(undefined);
    invalidateDeploymentQueriesMock.mockResolvedValue(undefined);
  });

  it("loads list/details/history queries", async () => {
    listAllCertificatesMock.mockResolvedValue([
      {
        certificateXref: "cert-1",
        userDomainCertId: "101",
        domain: "alpha.example.com",
        status: "ACTIVE",
        caProvider: "DIGICERT",
        san: false,
        wildcard: false,
      },
    ]);
    getCertificateDetailsRecordMock.mockResolvedValue({
      certificateXref: "cert-1",
      domain: "alpha.example.com",
      status: "ACTIVE",
    });
    getCertificateHistoryMock.mockResolvedValue({
      items: [],
      page: 0,
      size: 20,
      totalItems: 0,
      totalPages: 0,
    });

    const list = renderHook(() => useListCertificates(), {
      wrapper: createWrapper(),
    });
    const details = renderHook(() => useGetCertificateDetails("cert-1"), {
      wrapper: createWrapper(),
    });
    const history = renderHook(() => useGetCertificateHistory("101"), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(list.result.current.isSuccess).toBe(true);
      expect(details.result.current.isSuccess).toBe(true);
      expect(history.result.current.isSuccess).toBe(true);
    });
  });

  it("polls certificate history while lifecycle records are still transitioning", async () => {
    jest.useFakeTimers();
    getCertificateHistoryMock
      .mockResolvedValueOnce({
        items: [
          {
            certificateXref: "cert-renewing",
            domain: "alpha.example.com",
            status: "RENEWING",
          },
        ],
        page: 0,
        size: 20,
        totalItems: 1,
        totalPages: 1,
      })
      .mockResolvedValue({
        items: [
          {
            certificateXref: "cert-renewed",
            domain: "alpha.example.com",
            status: "RENEW_SUCCESS",
          },
        ],
        page: 0,
        size: 20,
        totalItems: 1,
        totalPages: 1,
      });

    try {
      const history = renderHook(() => useGetCertificateHistory("101"), {
        wrapper: createWrapper(),
      });

      await waitFor(() => expect(history.result.current.isSuccess).toBe(true));
      expect(getCertificateHistoryMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        jest.advanceTimersByTime(5000);
      });

      await waitFor(() => {
        expect(getCertificateHistoryMock).toHaveBeenCalledTimes(2);
      });

      await act(async () => {
        jest.advanceTimersByTime(5000);
      });

      expect(getCertificateHistoryMock).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it("polls only the transitional certificate instead of reloading the full list", async () => {
    jest.useFakeTimers();
    listAllCertificatesMock.mockResolvedValue([
      {
        certificateXref: "cert-pending",
        userDomainCertId: "101",
        domain: "alpha.example.com",
        status: "PENDING",
        rawStatus: "PENDING",
      },
    ]);
    getCertificateByXrefMock
      .mockResolvedValueOnce({
        certificateXref: "cert-pending",
        userDomainCertId: "101",
        domain: "alpha.example.com",
        status: "PENDING",
        rawStatus: "PENDING",
      })
      .mockResolvedValueOnce({
        certificateXref: "cert-pending",
        userDomainCertId: "101",
        domain: "alpha.example.com",
        status: "ACTIVE",
        rawStatus: "ACTIVE",
      });

    try {
      const list = renderHook(() => useListCertificates(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(getCertificateByXrefMock).toHaveBeenCalledTimes(1);
      });
      expect(listAllCertificatesMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        jest.advanceTimersByTime(5000);
      });

      await waitFor(() => {
        expect(list.result.current.data?.[0]?.status).toBe("ACTIVE");
      });
      expect(getCertificateByXrefMock).toHaveBeenCalledWith("cert-pending");
      expect(listCertificatesPageMock).not.toHaveBeenCalled();
      expect(listAllCertificatesMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        jest.advanceTimersByTime(5000);
      });
      expect(getCertificateByXrefMock).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it("recovers certificate polling after a transient status error", async () => {
    jest.useFakeTimers();
    listAllCertificatesMock.mockResolvedValue([
      {
        certificateXref: "cert-pending",
        userDomainCertId: "101",
        domain: "alpha.example.com",
        status: "PENDING",
        rawStatus: "PENDING",
      },
    ]);
    getCertificateByXrefMock
      .mockRejectedValueOnce(new Error("Temporary network failure"))
      .mockResolvedValueOnce({
        certificateXref: "cert-pending",
        userDomainCertId: "101",
        domain: "alpha.example.com",
        status: "ACTIVE",
        rawStatus: "ACTIVE",
      });

    try {
      const list = renderHook(() => useListCertificates(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(getCertificateByXrefMock).toHaveBeenCalledTimes(1);
      });
      expect(list.result.current.data?.[0]?.status).toBe("PENDING");

      await act(async () => {
        jest.advanceTimersByTime(10_000);
      });

      await waitFor(() => {
        expect(list.result.current.data?.[0]?.status).toBe("ACTIVE");
      });
      expect(getCertificateByXrefMock).toHaveBeenCalledTimes(2);
      expect(listAllCertificatesMock).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });

  it("merges a status update when the backend assigns a lifecycle id", async () => {
    listAllCertificatesMock.mockResolvedValue([
      {
        certificateXref: "cert-pending",
        domain: "alpha.example.com",
        status: "PENDING",
        rawStatus: "PENDING",
      },
    ]);
    getCertificateByXrefMock.mockResolvedValue({
      certificateXref: "cert-pending",
      userDomainCertId: "101",
      domain: "alpha.example.com",
      status: "ACTIVE",
      rawStatus: "ACTIVE",
    });

    const list = renderHook(() => useListCertificates(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(list.result.current.data?.[0]?.status).toBe("ACTIVE");
    });
    expect(list.result.current.data?.[0]?.userDomainCertId).toBe("101");
  });

  it("matches lifecycle id when an xref is not yet available", async () => {
    listAllCertificatesMock.mockResolvedValue([
      {
        userDomainCertId: "101",
        domain: "alpha.example.com",
        status: "PENDING",
        rawStatus: "PENDING",
      },
    ]);
    listCertificatesPageMock.mockResolvedValue({
      items: [
        {
          certificateXref: "cert-history",
          userDomainCertId: "99",
          domain: "alpha.example.com",
          status: "ACTIVE",
          rawStatus: "ACTIVE",
        },
        {
          certificateXref: "cert-current",
          userDomainCertId: "101",
          domain: "alpha.example.com",
          status: "ACTIVE",
          rawStatus: "ACTIVE",
        },
      ],
      page: 0,
      size: 100,
      totalItems: 2,
      totalPages: 1,
    });

    const list = renderHook(() => useListCertificates(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(list.result.current.data?.[0]?.certificateXref).toBe(
        "cert-current",
      );
    });
    expect(listCertificatesPageMock).toHaveBeenCalledWith({
      page: 0,
      size: 100,
      domain: "alpha.example.com",
    });
  });

  it("limits each certificate status polling tick to four requests", async () => {
    jest.useFakeTimers();
    const certificates = Array.from({ length: 10 }, (_, index) => ({
      certificateXref: `cert-${index}`,
      userDomainCertId: String(index),
      domain: `${index}.example.com`,
      status: "PENDING",
      rawStatus: "PENDING",
    }));
    listAllCertificatesMock.mockResolvedValue(certificates);
    getCertificateByXrefMock.mockImplementation((certificateXref: string) =>
      Promise.resolve(
        certificates.find(
          (certificate) => certificate.certificateXref === certificateXref,
        ),
      ),
    );

    try {
      renderHook(() => useListCertificates(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(getCertificateByXrefMock).toHaveBeenCalledTimes(4);
      });

      await act(async () => {
        jest.advanceTimersByTime(5000);
      });

      await waitFor(() => {
        expect(getCertificateByXrefMock).toHaveBeenCalledTimes(8);
      });
      expect(
        new Set(
          getCertificateByXrefMock.mock.calls.map(
            ([certificateXref]) => certificateXref,
          ),
        ).size,
      ).toBe(8);
    } finally {
      jest.useRealTimers();
    }
  });

  it("keeps polling renewal-success history when requested by the manage page", async () => {
    jest.useFakeTimers();
    getCertificateHistoryMock.mockResolvedValue({
      items: [
        {
          certificateXref: "cert-renew-success",
          domain: "alpha.example.com",
          status: "RENEW_SUCCESS",
        },
      ],
      page: 0,
      size: 20,
      totalItems: 1,
      totalPages: 1,
    });

    try {
      const history = renderHook(
        () => useGetCertificateHistory("101", 0, 20, { pollWhile: true }),
        {
          wrapper: createWrapper(),
        },
      );

      await waitFor(() => expect(history.result.current.isSuccess).toBe(true));
      expect(getCertificateHistoryMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        jest.advanceTimersByTime(5000);
      });

      await waitFor(() => {
        expect(getCertificateHistoryMock).toHaveBeenCalledTimes(2);
      });
    } finally {
      jest.useRealTimers();
    }
  });

  it("keeps deployment certificate data stable when polling is disabled", async () => {
    jest.useFakeTimers();
    listAllCertificatesMock.mockResolvedValue([
      {
        certificateXref: "cert-pending",
        userDomainCertId: "101",
        domain: "alpha.example.com",
        status: "PENDING",
      },
    ]);
    getCertificateHistoryMock.mockResolvedValue({
      items: [
        {
          certificateXref: "cert-renewing",
          domain: "alpha.example.com",
          status: "RENEWING",
        },
      ],
      page: 0,
      size: 20,
      totalItems: 1,
      totalPages: 1,
    });

    try {
      const queries = renderHook(
        () => ({
          certificates: useListCertificates({ pollWhilePending: false }),
          histories: useCertificateHistories(["101"], {
            pollWhilePending: false,
          }),
        }),
        { wrapper: createWrapper() },
      );

      await waitFor(() => {
        expect(queries.result.current.certificates.isSuccess).toBe(true);
        expect(queries.result.current.histories[0]?.isSuccess).toBe(true);
      });

      await act(async () => {
        await jest.advanceTimersByTimeAsync(10_000);
      });
      expect(listAllCertificatesMock).toHaveBeenCalledTimes(1);
      expect(listCertificatesPageMock).not.toHaveBeenCalled();
      expect(getCertificateHistoryMock).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });

  it("handles issue and manual-issue certificate mutations", async () => {
    issueCertificateMock.mockResolvedValue({
      certificateXref: "cert-2",
      domain: "beta.example.com",
      status: "PENDING",
    });
    issueManualCertificateMock.mockResolvedValue({
      certificateXref: "cert-3",
      domain: "gamma.example.com",
      status: "AWAITING_DNS",
    });

    const issue = renderHook(() => useIssueCertificateRequest(), {
      wrapper: createWrapper(),
    });
    const issueManual = renderHook(() => useIssueManualCertificateRequest(), {
      wrapper: createWrapper(),
    });

    await issue.result.current.mutateAsync({
      domain: "beta.example.com",
      wildcard: false,
      san: false,
      caProvider: "DIGICERT",
    });
    await issueManual.result.current.mutateAsync({
      domain: "gamma.example.com",
      wildcard: false,
      san: false,
    });
  });

  it("handles convert, DNS, renew, revoke and delete flows", async () => {
    convertToAutomatedMock.mockResolvedValue({
      certificateXref: "cert-1",
      domain: "alpha.example.com",
      status: "ACTIVE",
    });
    validateCertificateDnsMock.mockResolvedValue(undefined);
    renewCertificateMock.mockResolvedValue({
      certificateXref: "cert-1",
      domain: "alpha.example.com",
      status: "RENEWING",
    });
    revokeCertificateMock.mockResolvedValue({
      certificateXref: "cert-1",
      domain: "alpha.example.com",
      status: "REVOKING",
    });
    deleteCertificateMock.mockResolvedValue(undefined);

    const convert = renderHook(() => useConvertCertificateToAutomated(), {
      wrapper: createWrapper(),
    });
    const dns = renderHook(() => useCompleteDnsChallenge(), {
      wrapper: createWrapper(),
    });
    const renew = renderHook(() => useRenewCertificate(), {
      wrapper: createWrapper(),
    });
    const revoke = renderHook(() => useRevokeCertificate(), {
      wrapper: createWrapper(),
    });
    const remove = renderHook(() => useDeletePendingSSLCertificate(), {
      wrapper: createWrapper(),
    });

    await convert.result.current.mutateAsync({
      certificateXref: "cert-1",
      payload: {
        dnsMappings: [
          {
            domain: "alpha.example.com",
            credentialXref: "cred-dns-1",
          },
        ],
        deploymentTargets: ["cred-deploy-1"],
      },
    });
    await dns.result.current.mutateAsync({ certificateXref: "cert-1" });
    await renew.result.current.mutateAsync({
      certificateXref: "cert-1",
      deploymentTargets: ["cred-deploy-1"],
    });
    await revoke.result.current.mutateAsync({
      certificateXref: "cert-1",
      reason: "decommissioned",
    });
    await remove.result.current.mutateAsync({ userDomainCertId: "101" });

    expect(invalidateCertificateQueriesMock).toHaveBeenCalled();
    expect(invalidateAlertQueriesMock).toHaveBeenCalled();
    expect(invalidateAuditQueriesMock).toHaveBeenCalled();
  });

  it("loads TXT records and marks alert as read", async () => {
    getCertificateTxtRecordsMock.mockResolvedValue([
      { domain: "_acme-challenge.alpha.example.com", value: "txt-value" },
    ]);
    apiPatchMock.mockResolvedValue({ data: { success: true } });

    const txt = renderHook(() => useGetTxtRecords(), {
      wrapper: createWrapper(),
    });
    const mark = renderHook(() => useMarkAlertAsRead(), {
      wrapper: createWrapper(),
    });

    await txt.result.current.mutateAsync({ certificateXref: "cert-1" });
    await mark.result.current.mutateAsync(42);

    expect(apiPatchMock).toHaveBeenCalledWith("/api/alerts/42", {
      unread: false,
    });
  });

  it("throws when mark-alert API reports unsuccessful response", async () => {
    apiPatchMock.mockResolvedValue({ data: { success: false } });
    const mark = renderHook(() => useMarkAlertAsRead(), {
      wrapper: createWrapper(),
    });

    await expect(mark.result.current.mutateAsync(99)).rejects.toThrow(
      "Failed to mark alert as read",
    );
  });
});
