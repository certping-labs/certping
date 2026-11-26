// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { AxiosError, AxiosHeaders } from "axios";
import { toast } from "sonner";

import {
  useCertificateProfileEvents,
  useCertificateProfiles,
  useCreateCertificateProfile,
  useSyncSourceProfiles,
  useUpdateCertificateProfile,
} from "@/hooks/machine-identity/use-certificate-profiles";
import {
  useArchiveDevice,
  useDecommissionDevice,
  useRestoreDevice,
  useDevices,
} from "@/hooks/machine-identity/use-machine-devices";
import { useRequestCertificateDeviceSync } from "@/hooks/machine-identity/use-machine-certificates";
import {
  useStopDeviceSourceSync,
  useTriggerDeviceSourceSync,
} from "@/hooks/machine-identity/use-device-sources";
import { machineIdentityKeys } from "@/hooks/machine-identity/query-keys";
import * as profilesBackend from "@/lib/backend/machine-identity/profiles";
import * as devicesBackend from "@/lib/backend/machine-identity/devices";
import * as sourcesBackend from "@/lib/backend/machine-identity/sources";
import * as certificatesBackend from "@/lib/backend/machine-identity/certificates";

jest.mock("@/lib/backend/machine-identity/profiles");
jest.mock("@/lib/backend/machine-identity/devices");
jest.mock("@/lib/backend/machine-identity/sources");
jest.mock("@/lib/backend/machine-identity/certificates");

jest.mock("@/stores/auth-store", () => ({
  useAuthStore: () => ({ user: { organizationId: "org-1" } }),
}));

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), warning: jest.fn(), error: jest.fn() },
}));

const profiles = profilesBackend as jest.Mocked<typeof profilesBackend>;
const devices = devicesBackend as jest.Mocked<typeof devicesBackend>;
const sources = sourcesBackend as jest.Mocked<typeof sourcesBackend>;
const certificates = certificatesBackend as jest.Mocked<
  typeof certificatesBackend
>;
const toastMock = toast as jest.Mocked<typeof toast>;

function apiError(status: number, message?: string): AxiosError {
  const error = new AxiosError("Request failed");
  error.response = {
    status,
    statusText: "",
    data: message ? { message } : {},
    headers: new AxiosHeaders(),
    config: { headers: new AxiosHeaders() },
  };
  return error;
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return { queryClient, wrapper };
}

beforeEach(() => {
  jest.clearAllMocks();
  // The real resolvers are what the query keys are built from.
  profiles.resolveProfileListParams.mockImplementation(
    jest.requireActual("@/lib/backend/machine-identity/profiles")
      .resolveProfileListParams,
  );
  devices.resolveDeviceListParams.mockImplementation(
    jest.requireActual("@/lib/backend/machine-identity/devices")
      .resolveDeviceListParams,
  );
  devices.resolveDeviceEventParams.mockImplementation(
    jest.requireActual("@/lib/backend/machine-identity/devices")
      .resolveDeviceEventParams,
  );
  sources.resolveDeviceSourceEventParams.mockImplementation(
    jest.requireActual("@/lib/backend/machine-identity/sources")
      .resolveDeviceSourceEventParams,
  );
});

describe("certificate profile mutations", () => {
  it("tells the operator a draft was saved without contacting the provider", async () => {
    profiles.createCertificateProfile.mockResolvedValue({
      profileXref: "prof_1",
      lifecycleStatus: "DRAFT",
    } as never);
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useCreateCertificateProfile(), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync({
        name: "p",
        sourceXref: "src_1",
        lifecycleStatus: "DRAFT",
        targetPlatform: "WINDOWS",
        profileKind: "CERTIFICATE_ENROLLMENT",
        configuration: {},
      } as never);
    });

    expect(toastMock.success).toHaveBeenCalled();
    expect(profiles.createCertificateProfile).toHaveBeenCalled();
  });

  it("refreshes the profile list after a create", async () => {
    profiles.createCertificateProfile.mockResolvedValue({
      profileXref: "prof_1",
    } as never);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    const { result } = renderHook(() => useCreateCertificateProfile(), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync({
        name: "p",
        sourceXref: "src_1",
        lifecycleStatus: "ACTIVE",
        targetPlatform: "WINDOWS",
        profileKind: "CERTIFICATE_ENROLLMENT",
        configuration: {},
      } as never);
    });

    expect(invalidateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        queryKey: machineIdentityKeys.profiles("org-1"),
      }),
    );
  });

  async function attemptUpdate(
    error: unknown,
  ): Promise<jest.Mock["mock"]["calls"]> {
    profiles.updateCertificateProfile.mockRejectedValue(error);
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useUpdateCertificateProfile(), {
      wrapper,
    });
    await act(async () => {
      await result.current
        .mutateAsync({
          profileXref: "prof_1",
          input: {
            name: "p",
            lifecycleStatus: "ACTIVE",
            expectedVersion: 1,
            confirmReissuance: false,
            configuration: {},
          },
        } as never)
        .catch(() => undefined);
    });

    await waitFor(() => expect(toastMock.error).toHaveBeenCalled());
    return toastMock.error.mock.calls;
  }

  it("tells the operator what to do about a version conflict", async () => {
    // A 409 means the profile moved under them - a stale expectedVersion, or a
    // provider-owned profile. Echoing the backend's optimistic-locking wording
    // would not tell them the fix is to reload.
    const calls = await attemptUpdate(
      apiError(409, "Profile was modified by another request"),
    );

    expect(calls[0][0]).toBe(
      "This profile changed since you loaded it. Reload and try again.",
    );
  });

  it("falls back to the backend's message for other failures", async () => {
    const calls = await attemptUpdate(
      apiError(400, "keySize must be 2048 or greater"),
    );

    expect(calls[0][0]).toContain("keySize must be 2048");
  });

  it("reports a started discovery as accepted, not as finished", async () => {
    // Discovery is a 202: the agent has not answered yet.
    sources.listDeviceSources.mockResolvedValue([] as never);
    profiles.syncSourceProfiles.mockResolvedValue({
      status: "ACCEPTED",
      sourceXref: "src_1",
      requestXref: "req_1",
    } as never);
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useSyncSourceProfiles(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync("src_1");
    });

    expect(profiles.syncSourceProfiles).toHaveBeenCalledWith("src_1");
    expect(toastMock.success).toHaveBeenCalled();
    expect(toastMock.error).not.toHaveBeenCalled();
  });

  it("keeps a failed discovery from reading as success", async () => {
    profiles.syncSourceProfiles.mockRejectedValue(apiError(500));
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useSyncSourceProfiles(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync("src_1").catch(() => undefined);
    });

    await waitFor(() => expect(toastMock.error).toHaveBeenCalled());
    expect(toastMock.success).not.toHaveBeenCalled();
  });

  it("pages profile events under the profile's own key", async () => {
    profiles.listCertificateProfileEvents.mockResolvedValue({
      content: [],
      totalElements: 0,
    } as never);
    const { wrapper } = createWrapper();

    renderHook(() => useCertificateProfileEvents("prof_1", { page: 2 }), {
      wrapper,
    });

    await waitFor(() =>
      expect(profiles.listCertificateProfileEvents).toHaveBeenCalledWith(
        "prof_1",
        { page: 2 },
      ),
    );
  });

  it("does not fetch profile events without a profile", () => {
    const { wrapper } = createWrapper();
    renderHook(() => useCertificateProfileEvents(undefined), { wrapper });
    expect(profiles.listCertificateProfileEvents).not.toHaveBeenCalled();
  });

  it("lists profiles through the shared resolver", async () => {
    profiles.listCertificateProfiles.mockResolvedValue({
      content: [],
      totalElements: 0,
    } as never);
    const { wrapper } = createWrapper();

    renderHook(() => useCertificateProfiles({ sourceXref: "src_1" }), {
      wrapper,
    });

    await waitFor(() =>
      expect(profiles.listCertificateProfiles).toHaveBeenCalledWith({
        sourceXref: "src_1",
      }),
    );
  });
});

describe("device archive", () => {
  it("refreshes the inventory, the device and the summary tiles", async () => {
    devices.archiveDevice.mockResolvedValue(undefined as never);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    const { result } = renderHook(() => useArchiveDevice(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync("dev_1");
    });

    // The tiles count devices by status and exclude archived rows, so a stale
    // summary would keep showing a device the operator just took out of view.
    expect(invalidateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        queryKey: machineIdentityKeys.devices("org-1"),
      }),
    );
    expect(invalidateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        queryKey: machineIdentityKeys.summary("org-1"),
      }),
    );
    expect(toastMock.success).toHaveBeenCalled();
  });

  /**
   * The backend refuses while a usable certificate is still issued against the
   * device, and its message names how many. Surfacing that verbatim is the only
   * way the operator learns what to revoke.
   */
  it("surfaces the refusal when a usable certificate is still issued", async () => {
    devices.archiveDevice.mockRejectedValue(
      apiError(
        409,
        "Revoke or let expire 2 certificate(s) on this device before archiving it",
      ),
    );
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useArchiveDevice(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync("dev_1").catch(() => undefined);
    });

    await waitFor(() => expect(toastMock.error).toHaveBeenCalled());
    expect(toastMock.success).not.toHaveBeenCalled();
    expect(toastMock.error.mock.calls[0][0]).toContain("2 certificate(s)");
  });

  it("restores a device back into the inventory", async () => {
    devices.restoreDevice.mockResolvedValue(undefined as never);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    const { result } = renderHook(() => useRestoreDevice(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync("dev_1");
    });

    expect(invalidateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        queryKey: machineIdentityKeys.devices("org-1"),
      }),
    );
    expect(toastMock.success).toHaveBeenCalled();
  });
});

describe("device decommission", () => {
  it("refreshes the inventory and the device it just retired", async () => {
    devices.decommissionDevice.mockResolvedValue({
      deviceXref: "dev_1",
      status: "DECOMMISSIONED",
    } as never);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    const { result } = renderHook(() => useDecommissionDevice(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync("dev_1");
    });

    // Invalidating the whole `devices` prefix is what makes the list, the
    // detail page and the device's own event feed all reflect the new status -
    // every one of those keys is nested beneath it.
    const devicePrefix = machineIdentityKeys.devices("org-1");
    expect(invalidateSpy).toHaveBeenCalledWith(
      expect.objectContaining({ queryKey: devicePrefix }),
    );
    expect(
      machineIdentityKeys
        .device("org-1", "dev_1")
        .slice(0, devicePrefix.length),
    ).toEqual([...devicePrefix]);
    expect(toastMock.success).toHaveBeenCalled();
  });

  it("does not claim success when the API refuses", async () => {
    devices.decommissionDevice.mockRejectedValue(
      apiError(403, "You do not have permission"),
    );
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useDecommissionDevice(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync("dev_1").catch(() => undefined);
    });

    await waitFor(() => expect(toastMock.error).toHaveBeenCalled());
    expect(toastMock.success).not.toHaveBeenCalled();
    expect(toastMock.error.mock.calls[0][0]).toContain("permission");
  });
});

describe("certificate device check-in", () => {
  it("sends device xrefs and refreshes both certificate views", async () => {
    certificates.requestCertificateDeviceSync.mockResolvedValue({
      selectedDevices: 1,
      queuedDevices: 1,
      skippedDevices: 0,
      devices: [
        {
          deviceXref: "dev_1",
          status: "QUEUED",
          reason: null,
          certificateXrefs: ["crt_1"],
          nextAllowedAt: null,
        },
      ],
    });
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    const { result } = renderHook(() => useRequestCertificateDeviceSync(), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync({ deviceXrefs: ["dev_1"] });
    });

    expect(certificates.requestCertificateDeviceSync).toHaveBeenCalledWith({
      deviceXrefs: ["dev_1"],
    });
    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: machineIdentityKeys.certificates("org-1"),
    });
    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: machineIdentityKeys.devices("org-1"),
    });
    expect(toastMock.success).toHaveBeenCalledWith("Device check-in queued");
  });

  it("reports a skipped device as ineligible rather than successful", async () => {
    certificates.requestCertificateDeviceSync.mockResolvedValue({
      selectedDevices: 1,
      queuedDevices: 0,
      skippedDevices: 1,
      devices: [
        {
          deviceXref: "dev_1",
          status: "SKIPPED",
          reason: "OUTSIDE_RENEWAL_THRESHOLD",
          certificateXrefs: ["crt_1"],
          nextAllowedAt: null,
        },
      ],
    });
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useRequestCertificateDeviceSync(), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync({ deviceXrefs: ["dev_1"] });
    });

    // The endpoint already told us why, so the toast says it. "Not eligible"
    // on its own sends the operator hunting through the renewal panel for a
    // fact the response carried.
    expect(toastMock.warning).toHaveBeenCalledWith(
      "No check-in queued. Its certificate has not reached the profile's renewal window yet.",
    );
    expect(toastMock.success).not.toHaveBeenCalled();
  });

  it("falls back to a plain count when several devices were skipped", async () => {
    // With more than one device there is no single reason to report, and
    // listing every one would not fit a toast.
    certificates.requestCertificateDeviceSync.mockResolvedValue({
      selectedDevices: 2,
      queuedDevices: 0,
      skippedDevices: 2,
      devices: [
        {
          deviceXref: "dev_1",
          status: "SKIPPED",
          reason: "COOLDOWN_ACTIVE",
          certificateXrefs: [],
          nextAllowedAt: null,
        },
        {
          deviceXref: "dev_2",
          status: "SKIPPED",
          reason: "NO_MANAGED_DEVICE_ID",
          certificateXrefs: [],
          nextAllowedAt: null,
        },
      ],
    });
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useRequestCertificateDeviceSync(), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync({ deviceXrefs: ["dev_1", "dev_2"] });
    });

    expect(toastMock.warning).toHaveBeenCalledWith(
      "2 devices were not eligible for check-in",
    );
  });
});

describe("source sync controls", () => {
  it("refreshes the source list so the run appears immediately", async () => {
    sources.triggerDeviceSourceSync.mockResolvedValue({
      status: "ACCEPTED",
      sourceXref: "src_1",
      syncXref: "sync_1",
    } as never);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    const { result } = renderHook(() => useTriggerDeviceSourceSync(), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync("src_1");
    });

    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: machineIdentityKeys.sources("org-1"),
    });
  });

  it("labels stopping the schedule as future-only, never as a cancel", async () => {
    // There is no endpoint to cancel a run already delivered to the agent, so
    // the copy must not imply one.
    sources.stopDeviceSourceSync.mockResolvedValue({} as never);
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useStopDeviceSourceSync(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync("src_1");
    });

    expect(toastMock.success).toHaveBeenCalledWith("Future syncs stopped");
  });

  it("reports a rejected sync request", async () => {
    sources.triggerDeviceSourceSync.mockRejectedValue(apiError(423));
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useTriggerDeviceSourceSync(), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync("src_1").catch(() => undefined);
    });

    await waitFor(() => expect(toastMock.error).toHaveBeenCalled());
  });
});

describe("device list", () => {
  it("passes resolved params to the adapter", async () => {
    devices.listDevices.mockResolvedValue({
      content: [],
      totalElements: 0,
    } as never);
    const { wrapper } = createWrapper();

    renderHook(() => useDevices({ status: "ORPHANED", search: "laptop" }), {
      wrapper,
    });

    await waitFor(() =>
      expect(devices.listDevices).toHaveBeenCalledWith({
        status: "ORPHANED",
        search: "laptop",
      }),
    );
  });

  it("stays idle while disabled", () => {
    const { wrapper } = createWrapper();
    renderHook(() => useDevices({}, { enabled: false }), { wrapper });
    expect(devices.listDevices).not.toHaveBeenCalled();
  });
});
