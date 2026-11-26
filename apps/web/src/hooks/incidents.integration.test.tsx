// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import {
  getNotificationRetryDelay,
  useIncidentEscalations,
  useSystemAlerts,
  useSystemNotifications,
} from "@/hooks/incidents";

const apiGetMock = jest.fn();
const getSystemNotificationsMock = jest.fn();
const listIncidentHistoryMock = jest.fn();

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      get: (...args: unknown[]) => apiGetMock(...args),
      patch: jest.fn(),
    },
  };
});

jest.mock("@/lib/backend/notifications", () => ({
  getSystemNotifications: (...args: unknown[]) =>
    getSystemNotificationsMock(...args),
}));

jest.mock("@/lib/backend/integrations", () => ({
  createPagerDutyIncident: jest.fn(),
  createServiceNowIncident: jest.fn(),
  listIncidentHistory: (...args: unknown[]) => listIncidentHistoryMock(...args),
}));

jest.mock("sonner", () => ({
  toast: { error: jest.fn(), success: jest.fn() },
}));

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

describe("incident polling ownership", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    apiGetMock.mockReset();
    getSystemNotificationsMock.mockReset();
    listIncidentHistoryMock.mockReset();
    apiGetMock.mockResolvedValue({ data: { alerts: [] } });
    getSystemNotificationsMock.mockResolvedValue({
      items: [],
      page: 0,
      size: 20,
      totalElements: 0,
      totalPages: 0,
    });
    listIncidentHistoryMock.mockResolvedValue({
      items: [],
      page: 0,
      size: 50,
      totalItems: 0,
      totalPages: 0,
    });
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it.each([
    [0, 10_000],
    [1, 20_000],
    [2, 30_000],
    [3, 30_000],
  ])(
    "uses a bounded notification retry delay for failure count %i",
    (failureCount, expectedDelay) => {
      expect(getNotificationRetryDelay(failureCount)).toBe(expectedDelay);
    },
  );

  it("polls alerts only when the consumer explicitly owns polling", async () => {
    const owner = renderHook(
      () => useSystemAlerts({ enabled: true, poll: true }),
      { wrapper: createWrapper() },
    );

    await waitFor(() => expect(apiGetMock).toHaveBeenCalledTimes(1));
    await act(async () => {
      await jest.advanceTimersByTimeAsync(10_000);
    });
    await waitFor(() => expect(apiGetMock).toHaveBeenCalledTimes(2));
    owner.unmount();

    apiGetMock.mockClear();
    renderHook(() => useSystemAlerts({ enabled: true }), {
      wrapper: createWrapper(),
    });
    await waitFor(() => expect(apiGetMock).toHaveBeenCalledTimes(1));
    await act(async () => {
      await jest.advanceTimersByTimeAsync(20_000);
    });
    expect(apiGetMock).toHaveBeenCalledTimes(1);
  });

  it("keeps the last alerts visible and recovers with bounded backoff", async () => {
    const activeAlert = {
      id: 1,
      alertType: "CERTIFICATE_FAILURE",
      status: "OPEN",
      domain: "alpha.example.com",
      createdAt: "2026-07-23T00:00:00Z",
      message: "Certificate issuance is delayed",
      correlationId: null,
      severity: "WARNING",
      unread: true,
    };
    const resolvedAlert = { ...activeAlert, status: "RESOLVED" };
    apiGetMock
      .mockReset()
      .mockResolvedValueOnce({ data: { alerts: [activeAlert] } })
      .mockRejectedValueOnce(new Error("Temporary network failure"))
      .mockResolvedValue({ data: { alerts: [resolvedAlert] } });

    const owner = renderHook(
      () => useSystemAlerts({ enabled: true, poll: true }),
      { wrapper: createWrapper() },
    );

    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledTimes(1);
      expect(owner.result.current.data?.[0]?.status).toBe("OPEN");
    });

    await act(async () => {
      await jest.advanceTimersByTimeAsync(10_000);
    });
    expect(apiGetMock).toHaveBeenCalledTimes(2);
    expect(owner.result.current.data?.[0]?.status).toBe("OPEN");

    await act(async () => {
      await jest.advanceTimersByTimeAsync(10_000);
    });
    expect(apiGetMock).toHaveBeenCalledTimes(2);

    await act(async () => {
      await jest.advanceTimersByTimeAsync(10_000);
    });
    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledTimes(3);
      expect(owner.result.current.data?.[0]?.status).toBe("RESOLVED");
    });

    await act(async () => {
      await jest.advanceTimersByTimeAsync(10_000);
    });
    await waitFor(() => expect(apiGetMock).toHaveBeenCalledTimes(4));
  });

  it("does not poll notifications while the browser tab is hidden", async () => {
    renderHook(
      () => useSystemNotifications({}, { enabled: true, poll: true }),
      { wrapper: createWrapper() },
    );

    await waitFor(() =>
      expect(getSystemNotificationsMock).toHaveBeenCalledTimes(1),
    );
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });

    await act(async () => {
      await jest.advanceTimersByTimeAsync(20_000);
    });
    expect(getSystemNotificationsMock).toHaveBeenCalledTimes(1);
  });

  it("retries an initial notification failure with bounded exponential backoff", async () => {
    getSystemNotificationsMock
      .mockRejectedValueOnce(new Error("First failure"))
      .mockRejectedValueOnce(new Error("Second failure"))
      .mockResolvedValue({
        items: [],
        page: 0,
        size: 20,
        totalElements: 0,
        totalPages: 0,
      });

    const notifications = renderHook(
      () => useSystemNotifications({}, { enabled: true, poll: true }),
      { wrapper: createWrapper() },
    );
    await waitFor(() =>
      expect(getSystemNotificationsMock).toHaveBeenCalledTimes(1),
    );
    await waitFor(() =>
      expect(notifications.result.current.failureCount).toBe(1),
    );

    await act(async () => {
      await jest.advanceTimersByTimeAsync(30_000);
    });
    await waitFor(() => {
      expect(getSystemNotificationsMock).toHaveBeenCalledTimes(3);
      expect(notifications.result.current.isSuccess).toBe(true);
    });
  });

  it("loads escalation history once without starting an interval", async () => {
    renderHook(() => useIncidentEscalations({}, { enabled: true }), {
      wrapper: createWrapper(),
    });

    await waitFor(() =>
      expect(listIncidentHistoryMock).toHaveBeenCalledTimes(1),
    );
    await act(async () => {
      await jest.advanceTimersByTimeAsync(30_000);
    });

    expect(listIncidentHistoryMock).toHaveBeenCalledTimes(1);
  });
});

describe("useSystemAlerts status", () => {
  const record = {
    domain: "example.com",
    createdAt: "2026-09-12T00:00:00Z",
    message: "Message",
    correlationId: null,
    severity: "WARNING",
    unread: false,
  };

  beforeEach(() => {
    apiGetMock.mockReset();
  });

  it("keeps the status the backend sends, and marks a missing one unknown", async () => {
    apiGetMock.mockResolvedValue({
      data: {
        alerts: [
          {
            ...record,
            id: 1,
            alertType: "CERTIFICATE_FAILURE",
            status: "RESOLVED",
          },
          { ...record, id: 2, alertType: "DEPLOYMENT_FAILURE", status: "OPEN" },
          {
            ...record,
            id: 3,
            alertType: "CERTIFICATE_FAILURE",
            status: "FAILED",
          },
          { ...record, id: 4, alertType: "DEPLOYMENT_FAILURE", status: null },
        ],
      },
    });

    const { result } = renderHook(() => useSystemAlerts({ enabled: true }), {
      wrapper: createWrapper(),
    });

    await waitFor(() => expect(result.current.data).toHaveLength(4));
    const statusById = Object.fromEntries(
      (result.current.data ?? []).map((alert) => [alert.id, alert.status]),
    );
    expect(statusById).toEqual({
      "1": "RESOLVED",
      "2": "OPEN",
      "3": "FAILED",
      "4": "UNKNOWN",
    });
  });
});
