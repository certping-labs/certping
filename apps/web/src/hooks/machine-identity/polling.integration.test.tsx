// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import { useCertificateProfile } from "@/hooks/machine-identity/use-certificate-profiles";
import { useDeviceSources } from "@/hooks/machine-identity/use-device-sources";
import {
  useCertificate,
  useCertificates,
} from "@/hooks/machine-identity/use-machine-certificates";
import { machineIdentityKeys } from "@/hooks/machine-identity/query-keys";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import type {
  CertificateDetail,
  CertificateProfileResponse,
  DeviceSourceDto,
} from "@/types/machine-identity-backend";

const listDeviceSourcesMock = jest.fn();
const listCertificatesMock = jest.fn();
const getCertificateMock = jest.fn();
const getCertificateProfileMock = jest.fn();

jest.mock("@/lib/backend/machine-identity/sources", () => ({
  listDeviceSources: () => listDeviceSourcesMock(),
  listDeviceSourceEvents: jest.fn(),
  triggerDeviceSourceSync: jest.fn(),
  stopDeviceSourceSync: jest.fn(),
  resolveDeviceSourceEventParams: (params: unknown) => params,
}));

jest.mock("@/lib/backend/machine-identity/certificates", () => {
  const actual = jest.requireActual(
    "@/lib/backend/machine-identity/certificates",
  );
  return {
    ...actual,
    listCertificates: (...args: unknown[]) => listCertificatesMock(...args),
    getCertificate: (...args: unknown[]) => getCertificateMock(...args),
  };
});

jest.mock("@/lib/backend/machine-identity/profiles", () => {
  const actual = jest.requireActual("@/lib/backend/machine-identity/profiles");
  return {
    ...actual,
    getCertificateProfile: (...args: unknown[]) =>
      getCertificateProfileMock(...args),
  };
});

jest.mock("@/stores/auth-store", () => ({
  useAuthStore: () => ({ user: { organizationId: "org-1" } }),
}));

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

const { activeMs, liveMs, ambientMs } = MACHINE_IDENTITY_CONFIG.polling;

function source(
  syncStatus: DeviceSourceDto["sync"] extends null ? never : string,
  syncXref = "sync_1",
): DeviceSourceDto {
  return {
    sourceXref: "src_1",
    provider: "INTUNE",
    sourceCategory: "ENDPOINT_MANAGEMENT",
    connectionProfileRef: "intune-primary",
    displayName: "Intune QA",
    description: null,
    configurationMetadata: null,
    syncEnabled: true,
    status: "ACTIVE",
    firstAdvertisedAt: "2026-08-28T00:00:00Z",
    lastAdvertisedAt: "2026-08-28T00:00:00Z",
    health: null,
    sync: {
      syncXref,
      status: syncStatus,
      requestedAt: new Date().toISOString(),
      startedAt: null,
      completedAt: null,
      expectedDeviceCount: null,
      processedDeviceCount: null,
      failedDeviceCount: null,
      processedBatchCount: null,
      expectedBatchCount: null,
      completionReceived: false,
      lastError: null,
    } as DeviceSourceDto["sync"],
    deviceCount: 7,
  };
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return { queryClient, wrapper };
}

beforeEach(() => {
  jest.useFakeTimers();
  listDeviceSourcesMock.mockReset();
  listCertificatesMock.mockReset();
  getCertificateMock.mockReset();
  getCertificateProfileMock.mockReset();
});

afterEach(() => {
  jest.useRealTimers();
});

describe("device source polling", () => {
  it("follows a running sync closely", async () => {
    listDeviceSourcesMock.mockResolvedValue([source("RUNNING")]);
    const { wrapper } = createWrapper();

    renderHook(() => useDeviceSources(), { wrapper });
    await waitFor(() => expect(listDeviceSourcesMock).toHaveBeenCalledTimes(1));

    await act(async () => {
      jest.advanceTimersByTime(activeMs + 500);
    });
    await waitFor(() => expect(listDeviceSourcesMock).toHaveBeenCalledTimes(2));
  });

  it("drops to an ambient cadence once nothing is running", async () => {
    listDeviceSourcesMock.mockResolvedValue([source("OK")]);
    const { wrapper } = createWrapper();

    renderHook(() => useDeviceSources(), { wrapper });
    await waitFor(() => expect(listDeviceSourcesMock).toHaveBeenCalledTimes(1));

    // An idle source must not be polled at the in-flight cadence; that is the
    // difference between one request every three minutes and thirty-six.
    await act(async () => {
      jest.advanceTimersByTime(liveMs);
    });
    expect(listDeviceSourcesMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      jest.advanceTimersByTime(ambientMs);
    });
    await waitFor(() => expect(listDeviceSourcesMock).toHaveBeenCalledTimes(2));
  });

  it("refreshes the inventory when a sync run finishes", async () => {
    listDeviceSourcesMock
      .mockResolvedValueOnce([source("RUNNING")])
      .mockResolvedValue([source("OK")]);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    renderHook(() => useDeviceSources(), { wrapper });
    await waitFor(() => expect(listDeviceSourcesMock).toHaveBeenCalledTimes(1));

    await act(async () => {
      jest.advanceTimersByTime(activeMs + 500);
    });

    // The sync is the event. Every other screen learns about new devices from
    // this, instead of polling the inventory on the chance a run landed.
    await waitFor(() =>
      expect(invalidateSpy).toHaveBeenCalledWith({
        queryKey: machineIdentityKeys.devices("org-1"),
      }),
    );
    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: machineIdentityKeys.summary("org-1"),
    });
  });

  it("does not treat an already-finished sync on first load as news", async () => {
    listDeviceSourcesMock.mockResolvedValue([source("OK")]);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    renderHook(() => useDeviceSources(), { wrapper });
    await waitFor(() => expect(listDeviceSourcesMock).toHaveBeenCalledTimes(1));

    expect(invalidateSpy).not.toHaveBeenCalledWith({
      queryKey: machineIdentityKeys.devices("org-1"),
    });
  });
});

describe("certificate polling", () => {
  it("keeps the inventory current without any user action", async () => {
    // Device certificates are issued when a device runs SCEP; nothing in this
    // app precedes them, so a list left open would never show them.
    listCertificatesMock.mockResolvedValue({
      content: [],
      totalElements: 0,
      totalPages: 0,
      number: 0,
      size: 25,
    });
    const { wrapper } = createWrapper();

    renderHook(() => useCertificates(), { wrapper });
    await waitFor(() => expect(listCertificatesMock).toHaveBeenCalledTimes(1));

    await act(async () => {
      jest.advanceTimersByTime(liveMs + 500);
    });
    await waitFor(() => expect(listCertificatesMock).toHaveBeenCalledTimes(2));
  });

  it("watches a certificate whose device correlation has not arrived", async () => {
    getCertificateMock.mockResolvedValue({
      certificateXref: "crt_1",
      device: null,
      profile: null,
      enrollment: null,
    } as unknown as CertificateDetail);
    const { wrapper } = createWrapper();

    renderHook(() => useCertificate("crt_1"), { wrapper });
    await waitFor(() => expect(getCertificateMock).toHaveBeenCalledTimes(1));

    await act(async () => {
      jest.advanceTimersByTime(activeMs + 500);
    });
    await waitFor(() => expect(getCertificateMock).toHaveBeenCalledTimes(2));
  });

  it("stops watching a certificate once it has settled", async () => {
    getCertificateMock.mockResolvedValue({
      certificateXref: "crt_1",
      device: { deviceXref: "dev_1", deviceName: "Laptop", status: null },
      profile: { profileXref: "prof_1", name: "SCEP" },
      enrollment: { completedAt: "2026-08-28T09:24:00Z" },
    } as unknown as CertificateDetail);
    const { wrapper } = createWrapper();

    renderHook(() => useCertificate("crt_1"), { wrapper });
    await waitFor(() => expect(getCertificateMock).toHaveBeenCalledTimes(1));

    await act(async () => {
      jest.advanceTimersByTime(liveMs);
    });
    expect(getCertificateMock).toHaveBeenCalledTimes(1);
  });
});

describe("profile polling", () => {
  it("watches a profile while its provider push is pending", async () => {
    getCertificateProfileMock.mockResolvedValue({
      profileXref: "prof_1",
      providerSyncStatus: "PENDING",
    } as unknown as CertificateProfileResponse);
    const { wrapper } = createWrapper();

    renderHook(() => useCertificateProfile("prof_1"), { wrapper });
    await waitFor(() =>
      expect(getCertificateProfileMock).toHaveBeenCalledTimes(1),
    );

    await act(async () => {
      jest.advanceTimersByTime(activeMs + 500);
    });
    await waitFor(() =>
      expect(getCertificateProfileMock).toHaveBeenCalledTimes(2),
    );
  });

  it("leaves an in-sync profile alone", async () => {
    getCertificateProfileMock.mockResolvedValue({
      profileXref: "prof_1",
      providerSyncStatus: "IN_SYNC",
    } as unknown as CertificateProfileResponse);
    const { wrapper } = createWrapper();

    renderHook(() => useCertificateProfile("prof_1"), { wrapper });
    await waitFor(() =>
      expect(getCertificateProfileMock).toHaveBeenCalledTimes(1),
    );

    await act(async () => {
      jest.advanceTimersByTime(liveMs);
    });
    expect(getCertificateProfileMock).toHaveBeenCalledTimes(1);
  });
});
