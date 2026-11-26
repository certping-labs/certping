// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import { useAgentHealth, useAgentHealthCadence } from "@/hooks/agent";
import { useSystemAlerts, useUnreadAlertSummary } from "@/hooks/incidents";
import { useFeatureFlagsSync } from "@/hooks/use-feature-flags";
import { apiRoutes } from "@/lib/api";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";

const apiGetMock = jest.fn();
const listFeatureFlagsMock = jest.fn();
const useAuthMock = jest.fn();

// The shared setup stubs this module as always enabled; these tests need the real gate.
jest.mock("@/hooks/use-feature-flags", () =>
  jest.requireActual("@/hooks/use-feature-flags"),
);

jest.mock("@/lib/api", () => ({
  ...jest.requireActual("@/lib/api"),
  apiClient: {
    get: (url: string) => apiGetMock(url),
    patch: jest.fn(),
    put: jest.fn(),
  },
}));

jest.mock("@/lib/backend/feature-flags", () => ({
  getEffectiveFeatureFlags: () => listFeatureFlagsMock(),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => useAuthMock(),
}));

jest.mock("sonner", () => ({
  toast: {
    error: jest.fn(),
    success: jest.fn(),
    loading: jest.fn(),
    dismiss: jest.fn(),
  },
}));

const ORG_USER = { isAuthenticated: true, user: { organizationId: "42" } };
const NO_ORG_USER = { isAuthenticated: true, user: { organizationId: null } };

interface GatedPoller {
  name: string;
  featureKey: string;
  url: string;
  pollMs: number | null;
  /** The endpoint refuses a session without an organization (`fromJwt()`). */
  needsOrganization: boolean;
  useHook: () => unknown;
}

const POLLERS: GatedPoller[] = [
  {
    name: "useSystemAlerts",
    featureKey: FEATURE_FLAGS.ALERTS,
    url: apiRoutes.query.incidents.sslAlerts,
    pollMs: 10_000,
    needsOrganization: false,
    useHook: () => useSystemAlerts({ poll: true }),
  },
  {
    name: "useUnreadAlertSummary",
    featureKey: FEATURE_FLAGS.ALERTS,
    url: apiRoutes.query.incidents.sslAlerts,
    pollMs: 10_000,
    needsOrganization: false,
    useHook: () => useUnreadAlertSummary({ poll: true }),
  },
  {
    name: "useAgentHealth",
    featureKey: FEATURE_FLAGS.AGENT_HEALTH_MONITORING,
    url: apiRoutes.query.agent.health,
    pollMs: 30_000,
    needsOrganization: true,
    useHook: () => useAgentHealth(),
  },
  {
    name: "useAgentHealthCadence",
    featureKey: FEATURE_FLAGS.AGENT_HEALTH_MONITORING,
    url: apiRoutes.query.agent.healthCadence,
    pollMs: null,
    needsOrganization: true,
    useHook: () => useAgentHealthCadence(),
  },
];

function flagsWith(
  featureKey: string,
  enabled: boolean,
): Record<string, boolean> {
  return { [featureKey]: enabled };
}

function renderPoller(poller: GatedPoller) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  // AuthProvider mounts the single flag fetcher; mirror that here.
  return renderHook(
    () => {
      useFeatureFlagsSync();
      return poller.useHook();
    },
    { wrapper },
  );
}

const callsTo = (url: string): number =>
  apiGetMock.mock.calls.filter(([calledUrl]) => calledUrl === url).length;

const advance = async (ms: number) => {
  await act(async () => {
    await jest.advanceTimersByTimeAsync(ms);
  });
};

describe.each(POLLERS)("$name behind $featureKey", (poller) => {
  beforeEach(() => {
    jest.useFakeTimers();
    useFeatureFlagStore.getState().reset();
    apiGetMock.mockReset();
    listFeatureFlagsMock.mockReset();
    apiGetMock.mockResolvedValue({ data: { alerts: [] } });
    useAuthMock.mockReturnValue(ORG_USER);
    useAuthStore.setState({ user: ORG_USER.user as never });
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("sends no request when the feature is off", async () => {
    listFeatureFlagsMock.mockResolvedValue(flagsWith(poller.featureKey, false));

    renderPoller(poller);
    await waitFor(() =>
      expect(useFeatureFlagStore.getState().hasLoaded).toBe(true),
    );
    await advance(60_000);

    expect(callsTo(poller.url)).toBe(0);
  });

  it("sends no request while the flags are still loading", async () => {
    listFeatureFlagsMock.mockReturnValue(new Promise(() => undefined));

    renderPoller(poller);
    await advance(60_000);

    expect(listFeatureFlagsMock).toHaveBeenCalled();
    expect(callsTo(poller.url)).toBe(0);
  });

  it("fetches as before when the feature is on", async () => {
    listFeatureFlagsMock.mockResolvedValue(flagsWith(poller.featureKey, true));

    renderPoller(poller);
    await waitFor(() => expect(callsTo(poller.url)).toBe(1));

    if (poller.pollMs !== null) {
      await advance(poller.pollMs);
      await waitFor(() => expect(callsTo(poller.url)).toBe(2));
    }
  });

  it("asks only endpoints that serve a session without an organization", async () => {
    useAuthMock.mockReturnValue(NO_ORG_USER);
    useAuthStore.setState({ user: NO_ORG_USER.user as never });

    renderPoller(poller);
    await advance(1_000);

    expect(listFeatureFlagsMock).not.toHaveBeenCalled();
    expect(callsTo(poller.url)).toBe(poller.needsOrganization ? 0 : 1);
  });
});
