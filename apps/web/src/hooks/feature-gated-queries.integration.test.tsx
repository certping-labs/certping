// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";

import { useCanAddCredential } from "@/hooks/credentials";
import { useDiscoveryConfigs } from "@/hooks/discovery";
import { useIncidentEscalations } from "@/hooks/incidents";
import { useGetIntegration, useListIntegrations } from "@/hooks/integrations";
import { useCertificateProfiles } from "@/hooks/machine-identity/use-certificate-profiles";
import { useIotSummary } from "@/hooks/machine-identity/use-machine-identity-summary";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { server } from "@/test/msw/server";
import type { SsoUser } from "@/types/auth";

// The shared setup stubs every flag as on. These suites prove the queries wait
// for the real store, so they use the real hooks.
jest.unmock("@/hooks/use-feature-flags");

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;
const DISCOVERY_CONFIGS_URL = `${API_BASE_URL}/api/v1/discovery/trigger`;
const IOT_SUMMARY_URL = `${API_BASE_URL}/api/v1/iot/summary`;
const PROFILES_URL = `${API_BASE_URL}/api/v1/machine-identity/profiles`;

const USER: SsoUser = {
  id: "u1",
  email: "operator@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions: ["certificate:read", "credential:create"],
  authMethod: "LOCAL",
} as SsoUser;

const requests: string[] = [];

function wrapper({ children }: { children: React.ReactNode }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

function setFlags(effectiveMap: Record<string, boolean>) {
  act(() => {
    useFeatureFlagStore.getState().setEffectiveMap(effectiveMap);
  });
}

/** Lets any query that was going to start do so, without waiting on time. */
async function settle() {
  await act(async () => {
    await Promise.resolve();
  });
}

beforeEach(() => {
  requests.length = 0;
  useFeatureFlagStore.getState().reset();
  useAuthStore.setState({ user: USER });
  server.use(
    http.get(DISCOVERY_CONFIGS_URL, () => {
      requests.push("discovery-configs");
      return HttpResponse.json([]);
    }),
    http.get(IOT_SUMMARY_URL, () => {
      requests.push("iot-summary");
      return HttpResponse.json({});
    }),
    http.get(PROFILES_URL, () => {
      requests.push("profiles");
      return HttpResponse.json({ content: [], totalElements: 0 });
    }),
    http.get(`${API_BASE_URL}/api/v1/integrations`, () => {
      requests.push("integrations");
      return HttpResponse.json([]);
    }),
    http.get(`${API_BASE_URL}/api/v1/integrations/:id`, () => {
      requests.push("integration");
      return HttpResponse.json({ id: 4 });
    }),
    http.get("*/api/v1/incidents", () => {
      requests.push("escalations");
      return HttpResponse.json({ items: [], total: 0 });
    }),
  );
});

afterEach(() => {
  server.resetHandlers();
});

describe("discovery queries", () => {
  it("send nothing while flags are unknown, then load once DISCOVERY is on", async () => {
    const { unmount } = renderHook(() => useDiscoveryConfigs(), { wrapper });
    await settle();
    expect(requests).toEqual([]);

    setFlags({ [FEATURE_FLAGS.DISCOVERY]: true });

    await waitFor(() => expect(requests).toEqual(["discovery-configs"]));
    unmount();
  });

  it("send nothing when DISCOVERY is off or missing", async () => {
    setFlags({ [FEATURE_FLAGS.CERTIFICATE_ISSUANCE]: true });
    const { result, unmount } = renderHook(() => useDiscoveryConfigs(), {
      wrapper,
    });
    await settle();

    expect(requests).toEqual([]);
    expect(result.current.fetchStatus).toBe("idle");
    unmount();
  });

  it("send nothing when the flag fetch failed", async () => {
    act(() => {
      useFeatureFlagStore.getState().markLoadFailed();
    });
    const { unmount } = renderHook(() => useDiscoveryConfigs(), { wrapper });
    await settle();

    expect(requests).toEqual([]);
    unmount();
  });
});

describe("machine identity queries", () => {
  it("wait for IOT_DEVICE_MANAGEMENT before reading the fleet summary", async () => {
    setFlags({ [FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT]: false });
    const { unmount } = renderHook(() => useIotSummary(), { wrapper });
    await settle();
    expect(requests).toEqual([]);

    setFlags({ [FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT]: true });

    await waitFor(() => expect(requests).toEqual(["iot-summary"]));
    unmount();
  });

  it("gate profiles on their own flag, independently of devices", async () => {
    setFlags({
      [FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT]: false,
      [FEATURE_FLAGS.IOT_CERTIFICATE_PROFILE_MANAGEMENT]: true,
    });
    const { unmount } = renderHook(
      () => {
        useIotSummary();
        useCertificateProfiles();
      },
      { wrapper },
    );

    await waitFor(() => expect(requests).toEqual(["profiles"]));
    unmount();
  });
});

describe("integrations queries", () => {
  const useIntegrationQueries = () => {
    useListIntegrations();
    useGetIntegration(4);
    useIncidentEscalations();
  };

  it("send nothing while INTEGRATIONS is off", async () => {
    setFlags({ [FEATURE_FLAGS.INTEGRATIONS]: false });
    const { unmount } = renderHook(useIntegrationQueries, { wrapper });
    await settle();

    expect(requests).toEqual([]);
    unmount();
  });

  it("load integrations and escalations once INTEGRATIONS is on", async () => {
    setFlags({ [FEATURE_FLAGS.INTEGRATIONS]: false });
    const { unmount } = renderHook(useIntegrationQueries, { wrapper });
    await settle();
    expect(requests).toEqual([]);

    setFlags({ [FEATURE_FLAGS.INTEGRATIONS]: true });

    await waitFor(() =>
      expect([...requests].sort()).toEqual([
        "escalations",
        "integration",
        "integrations",
      ]),
    );
    unmount();
  });
});

describe("useCanAddCredential", () => {
  it.each([
    [{}, "DNS", false],
    [{ CREDENTIALS_MANAGEMENT: true }, "DNS", false],
    [{ DNS_CREDENTIALS: true }, "DNS", false],
    [{ CREDENTIALS_MANAGEMENT: true, DNS_CREDENTIALS: true }, "DNS", true],
    [{ CREDENTIALS_MANAGEMENT: true }, "DEPLOYMENT", false],
    [{ CERTIFICATE_DEPLOYMENT: true }, "DEPLOYMENT", false],
    [
      { CREDENTIALS_MANAGEMENT: true, CERTIFICATE_DEPLOYMENT: true },
      "DEPLOYMENT",
      true,
    ],
  ] as const)(
    "with flags %j allows adding a %s credential: %s",
    (effectiveMap, type, expected) => {
      setFlags(effectiveMap);
      const { result } = renderHook(() => useCanAddCredential(type));
      expect(result.current).toBe(expected);
    },
  );

  it("needs the create permission even when the features are on", () => {
    useAuthStore.setState({
      user: { ...USER, permissions: ["credential:read"] },
    });
    setFlags({ CREDENTIALS_MANAGEMENT: true, CERTIFICATE_DEPLOYMENT: true });

    const { result } = renderHook(() => useCanAddCredential("DNS"));

    expect(result.current).toBe(false);
  });
});
