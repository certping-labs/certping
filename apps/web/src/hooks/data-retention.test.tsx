// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import {
  AUDIT_RETENTION_KEY,
  useAuditRetention,
  useSetAuditRetention,
} from "@/hooks/data-retention";
import {
  getAuditRetention,
  updateAuditRetention,
} from "@/lib/backend/audit-retention";
import { formatDateTime } from "@/lib/utils";
import {
  auditRetentionFixture,
  unconfirmedAuditRetentionFixture,
} from "@/test/fixtures/audit-retention";

const mockToastSuccess = jest.fn();
const mockToastError = jest.fn();

jest.mock("sonner", () => ({
  toast: {
    success: (message: string) => mockToastSuccess(message),
    error: (message: string) => mockToastError(message),
  },
}));

jest.mock("@/lib/backend/audit-retention", () => ({
  ...jest.requireActual("@/lib/backend/audit-retention"),
  getAuditRetention: jest.fn(),
  updateAuditRetention: jest.fn(),
}));

function setup() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return { queryClient, wrapper };
}

beforeEach(() => {
  mockToastSuccess.mockClear();
  mockToastError.mockClear();
});

describe("useAuditRetention", () => {
  it("does not ask when the caller isn't a super admin", () => {
    const { wrapper } = setup();
    const { result } = renderHook(() => useAuditRetention({ enabled: false }), {
      wrapper,
    });
    expect(result.current.fetchStatus).toBe("idle");
    expect(getAuditRetention).not.toHaveBeenCalled();
  });

  it("loads the setting for a super admin", async () => {
    jest
      .mocked(getAuditRetention)
      .mockResolvedValue(unconfirmedAuditRetentionFixture());
    const { wrapper } = setup();
    const { result } = renderHook(() => useAuditRetention({ enabled: true }), {
      wrapper,
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.confirmed).toBe(false);
  });

  it("does not retry a refusal", async () => {
    jest.mocked(getAuditRetention).mockRejectedValue(new Error("403"));
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    });
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useAuditRetention({ enabled: true }), {
      wrapper,
    });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(getAuditRetention).toHaveBeenCalledTimes(1);
  });
});

describe("useSetAuditRetention", () => {
  it("sends months and reason, then caches the confirmed setting", async () => {
    const saved = auditRetentionFixture({ months: 24, previousMonths: 12 });
    jest.mocked(updateAuditRetention).mockResolvedValue(saved);
    const { queryClient, wrapper } = setup();
    queryClient.setQueryData(
      AUDIT_RETENTION_KEY,
      unconfirmedAuditRetentionFixture(),
    );

    const { result } = renderHook(() => useSetAuditRetention(), { wrapper });
    await act(() =>
      result.current.mutateAsync({ months: 24, reason: "Contract" }),
    );

    expect(updateAuditRetention).toHaveBeenCalledWith({
      months: 24,
      reason: "Contract",
    });
    expect(queryClient.getQueryData(AUDIT_RETENTION_KEY)).toEqual(saved);
    expect(mockToastSuccess).toHaveBeenCalledWith(
      `Audit retention confirmed: 2 years. Applies from ${formatDateTime("2026-01-02T04:30:00Z")}.`,
    );
  });

  it("omits the date when the response has none", async () => {
    jest
      .mocked(updateAuditRetention)
      .mockResolvedValue(auditRetentionFixture({ effectiveFrom: null }));
    const { wrapper } = setup();
    const { result } = renderHook(() => useSetAuditRetention(), { wrapper });
    await act(() => result.current.mutateAsync({ months: 12, reason: "Ok" }));
    expect(mockToastSuccess).toHaveBeenCalledWith(
      "Audit retention confirmed: 1 year.",
    );
  });

  it("leaves errors to the form instead of toasting", async () => {
    jest.mocked(updateAuditRetention).mockRejectedValue(new Error("nope"));
    const { wrapper } = setup();
    const { result } = renderHook(() => useSetAuditRetention(), { wrapper });

    await act(async () => {
      await result.current
        .mutateAsync({ months: 5, reason: "x" })
        .catch(() => undefined);
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(mockToastError).not.toHaveBeenCalled();
    expect(mockToastSuccess).not.toHaveBeenCalled();
  });
});
