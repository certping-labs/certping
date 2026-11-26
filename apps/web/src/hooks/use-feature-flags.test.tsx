// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import { useAuthStore } from "@/stores/auth-store";
import {
  FEATURE_LOCK_COOLDOWN_MS,
  useFeatureFlagStore,
} from "@/stores/feature-flag-store";

type EffectiveMap = Record<string, boolean>;

// The shared jest setup stubs this module as always-enabled for unrelated
// suites. This suite is about the real fetch lifecycle and semantics.
const {
  featureFlagsQueryKey,
  useFeatureAvailability,
  useFeatureFlags,
  useFeatureFlagsSync,
  useIsFeatureEnabled,
  useIsOrgFeatureEnabled,
  useIsRouteAvailable,
  useRetryFeatureFlags,
} = jest.requireActual<typeof import("@/hooks/use-feature-flags")>(
  "@/hooks/use-feature-flags",
);

const effectiveFlagsMock = jest.fn();
const useAuthMock = jest.fn();

jest.mock("@/lib/backend/feature-flags", () => ({
  getEffectiveFeatureFlags: (...args: unknown[]) => effectiveFlagsMock(...args),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => useAuthMock(),
}));

const POLL_MS = 60_000;
const KEY = "IOT_DEVICE_MANAGEMENT";

function response(enabled: boolean): EffectiveMap {
  return { [KEY]: enabled };
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

/** The sync hook plus the readers a component would use, in one render. */
function useSyncedFlags() {
  useFeatureFlagsSync();
  return {
    flags: useFeatureFlags(),
    availability: useFeatureAvailability(KEY),
    isEnabled: useIsFeatureEnabled(KEY),
  };
}

describe("useFeatureFlagsSync and readers", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    effectiveFlagsMock.mockReset();
    useFeatureFlagStore.getState().reset();
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      user: { organizationId: "42" },
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("reports pending until the first answer, then the real value", async () => {
    let resolve: (value: EffectiveMap) => void = () => undefined;
    effectiveFlagsMock.mockReturnValue(
      new Promise<EffectiveMap>((r) => {
        resolve = r;
      }),
    );
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useSyncedFlags(), { wrapper });
    expect(result.current.availability).toBe("pending");
    expect(result.current.isEnabled).toBe(false);
    expect(result.current.flags.isReady).toBe(false);

    await act(async () => resolve(response(true)));

    await waitFor(() => expect(result.current.availability).toBe("on"));
    expect(result.current.flags.isEnabled(KEY)).toBe(true);
    expect(result.current.flags.isEnabled("MISSING_KEY")).toBe(false);
  });

  it("keeps polling after the first successful fetch", async () => {
    effectiveFlagsMock.mockResolvedValue(response(true));
    const { wrapper } = createWrapper();

    renderHook(() => useFeatureFlagsSync(), { wrapper });
    await waitFor(() => expect(effectiveFlagsMock).toHaveBeenCalledTimes(1));

    await act(async () => {
      jest.advanceTimersByTime(POLL_MS + 1_000);
    });

    await waitFor(() => expect(effectiveFlagsMock).toHaveBeenCalledTimes(2));
  });

  it("applies a flag turned off between polls", async () => {
    effectiveFlagsMock
      .mockResolvedValueOnce(response(true))
      .mockResolvedValue(response(false));
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useSyncedFlags(), { wrapper });
    await waitFor(() => expect(result.current.isEnabled).toBe(true));

    await act(async () => {
      jest.advanceTimersByTime(POLL_MS + 1_000);
    });

    await waitFor(() => expect(result.current.availability).toBe("off"));
  });

  it("refetches when a toggle invalidates the flag query", async () => {
    effectiveFlagsMock
      .mockResolvedValueOnce(response(true))
      .mockResolvedValue(response(false));
    const { queryClient, wrapper } = createWrapper();

    const { result } = renderHook(() => useSyncedFlags(), { wrapper });
    await waitFor(() => expect(result.current.isEnabled).toBe(true));

    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: ["feature-flags"] });
    });

    await waitFor(() => expect(result.current.isEnabled).toBe(false));
  });

  it("does not fetch without an organization and treats flags as not applicable", async () => {
    useAuthMock.mockReturnValue({ isAuthenticated: true, user: {} });
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useSyncedFlags(), { wrapper });

    await act(async () => {
      jest.advanceTimersByTime(POLL_MS * 3);
    });

    expect(effectiveFlagsMock).not.toHaveBeenCalled();
    expect(result.current.flags.status).toBe("not-applicable");
    expect(result.current.availability).toBe("on");
  });

  it("returns to pending when an organization appears mid-session", async () => {
    useAuthMock.mockReturnValue({ isAuthenticated: true, user: {} });
    effectiveFlagsMock.mockReturnValue(new Promise(() => undefined));
    const { wrapper } = createWrapper();

    const { result, rerender } = renderHook(() => useSyncedFlags(), {
      wrapper,
    });
    await waitFor(() => expect(result.current.availability).toBe("on"));

    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      user: { organizationId: "42" },
    });
    rerender();

    await waitFor(() => expect(result.current.availability).toBe("pending"));
  });

  it("settles as error (not open) when the first fetch fails, and retries", async () => {
    effectiveFlagsMock
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValue(response(true));
    const { wrapper } = createWrapper();

    const { result } = renderHook(
      () => ({ synced: useSyncedFlags(), retry: useRetryFeatureFlags() }),
      { wrapper },
    );

    await waitFor(() =>
      expect(result.current.synced.availability).toBe("error"),
    );
    expect(result.current.synced.isEnabled).toBe(false);
    expect(result.current.synced.flags.isReady).toBe(true);

    await act(async () => result.current.retry.retry());

    await waitFor(() => expect(result.current.synced.availability).toBe("on"));
  });

  it("keeps last-known values when a refetch fails", async () => {
    effectiveFlagsMock
      .mockResolvedValueOnce(response(true))
      .mockRejectedValue(new Error("blip"));
    const { queryClient, wrapper } = createWrapper();

    const { result } = renderHook(() => useSyncedFlags(), { wrapper });
    await waitFor(() => expect(result.current.isEnabled).toBe(true));

    await act(async () => {
      await queryClient.refetchQueries({ queryKey: ["feature-flags"] });
    });

    expect(result.current.availability).toBe("on");
  });

  it("scopes the query key to the effective map of the organization", () => {
    expect(featureFlagsQueryKey("42")).toEqual([
      "feature-flags",
      "effective",
      "42",
    ]);
    expect(featureFlagsQueryKey(undefined)).toEqual([
      "feature-flags",
      "effective",
      null,
    ]);
  });

  it("does not reset on first mount, so seeded answers survive", async () => {
    effectiveFlagsMock.mockReturnValue(new Promise(() => undefined));
    useFeatureFlagStore.getState().setEffectiveMap({ [KEY]: true });
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useSyncedFlags(), { wrapper });

    expect(result.current.availability).toBe("on");
  });

  it("resets the answer and every cooldown when the organization changes", async () => {
    effectiveFlagsMock.mockResolvedValueOnce(response(true));
    const { wrapper } = createWrapper();
    const { result, rerender } = renderHook(() => useSyncedFlags(), {
      wrapper,
    });
    await waitFor(() => expect(result.current.isEnabled).toBe(true));
    useFeatureFlagStore.getState().markFeatureLocked("OTHER_KEY");

    effectiveFlagsMock.mockReturnValue(new Promise(() => undefined));
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      user: { organizationId: "43" },
    });
    rerender();

    await waitFor(() => expect(result.current.availability).toBe("pending"));
    expect(useFeatureFlagStore.getState().lockedAt).toEqual({});
  });

  it("re-applies an identical refetch once a 423 cooldown has ended", async () => {
    effectiveFlagsMock.mockResolvedValue(response(true));
    const { queryClient, wrapper } = createWrapper();
    const { result } = renderHook(() => useSyncedFlags(), { wrapper });
    await waitFor(() => expect(result.current.isEnabled).toBe(true));

    act(() => {
      useFeatureFlagStore.getState().markFeatureLocked(KEY);
    });
    expect(result.current.availability).toBe("off");

    await act(async () => {
      await queryClient.refetchQueries({ queryKey: ["feature-flags"] });
    });
    expect(result.current.availability).toBe("off");

    await act(async () => {
      jest.advanceTimersByTime(FEATURE_LOCK_COOLDOWN_MS);
      await queryClient.refetchQueries({ queryKey: ["feature-flags"] });
    });
    await waitFor(() => expect(result.current.availability).toBe("on"));
  });
});

describe("useIsRouteAvailable and useIsOrgFeatureEnabled", () => {
  afterEach(() => {
    useFeatureFlagStore.getState().reset();
    useAuthStore.setState({ user: null, isSuperAdmin: false });
  });

  it("answers routes by the gate's rule, super-admin exemptions included", () => {
    useFeatureFlagStore.getState().setEffectiveMap({ DISCOVERY: true });
    useAuthStore.setState({ isSuperAdmin: true });

    const { result } = renderHook(() => useIsRouteAvailable());

    expect(result.current("/cert-manager/discovery")).toBe(true);
    expect(result.current("/cert-manager/cryptography")).toBe(false);
    // Recording never stops: the platform audit log is exempt for a super admin.
    expect(result.current("/settings/audit-logs")).toBe(true);
  });

  it("hides organization-only routes from a session without one", () => {
    useFeatureFlagStore.getState().markNotApplicable();
    useAuthStore.setState({ isSuperAdmin: true });

    const { result } = renderHook(() => useIsRouteAvailable());

    expect(result.current("/cert-manager/discovery")).toBe(false);
    expect(result.current("/settings/audit-logs")).toBe(true);
  });

  it("keeps organization-scoped queries off without an organization", () => {
    useFeatureFlagStore.getState().markNotApplicable();
    useAuthStore.setState({ user: { organizationId: null } as never });
    const { result: noOrg } = renderHook(() => useIsOrgFeatureEnabled(KEY));
    expect(noOrg.current).toBe(false);

    useFeatureFlagStore.getState().setEffectiveMap({ [KEY]: true });
    useAuthStore.setState({ user: { organizationId: "42" } as never });
    const { result: inOrg } = renderHook(() => useIsOrgFeatureEnabled(KEY));
    expect(inOrg.current).toBe(true);
  });
});
