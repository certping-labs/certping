// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook } from "@testing-library/react";

import {
  useDeleteDiscoveryConfig,
  useRerunAllDiscoveryConfigs,
  useRerunDiscoveryConfig,
  useTriggerDiscovery,
} from "@/hooks/discovery";
import { PERMISSIONS } from "@/lib/authz";
import { useAuthStore } from "@/stores/auth-store";

const mockTriggerDiscovery = jest.fn();
const mockRerunDiscoveryConfig = jest.fn();
const mockRerunAllDiscoveryConfigs = jest.fn();
const mockDeleteDiscoveryConfig = jest.fn();

jest.mock("@/lib/backend/discovery", () => ({
  triggerDiscovery: (...args: unknown[]) => mockTriggerDiscovery(...args),
  rerunDiscoveryConfig: (...args: unknown[]) =>
    mockRerunDiscoveryConfig(...args),
  rerunAllDiscoveryConfigs: (...args: unknown[]) =>
    mockRerunAllDiscoveryConfigs(...args),
  deleteDiscoveryConfig: (...args: unknown[]) =>
    mockDeleteDiscoveryConfig(...args),
}));

jest.mock("sonner", () => ({
  toast: { error: jest.fn(), success: jest.fn() },
}));

const runResponse = {
  completedAt: null,
  configId: 7,
  credentialXref: "cred-1",
  message: "started",
  requestId: "req-1",
  startedAt: "2026-07-25T00:00:00Z",
  status: "RUNNING",
  targetType: "KUBERNETES",
};

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false }, queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

const signInWith = (permissions: string[]) => {
  useAuthStore.setState({
    expiresAt: Date.now() + 60_000,
    isLoading: false,
    isSuperAdmin: false,
    user: {
      authMethod: "LOCAL",
      email: "deployer@example.com",
      id: "user-1",
      organizationId: "org-1",
      organizationName: "Org",
      permissions,
      roles: ["DEPLOYMENT_MANAGER"],
    },
  });
};

/** DEPLOYMENT_MANAGER-like grant: deploy but neither issue nor delete. */
const DEPLOYER_PERMISSIONS = [
  PERMISSIONS.certificatesView,
  PERMISSIONS.certificatesDeploy,
  PERMISSIONS.credentialsView,
];

describe("discovery mutation permissions", () => {
  beforeEach(() => {
    mockTriggerDiscovery.mockResolvedValue(runResponse);
    mockRerunDiscoveryConfig.mockResolvedValue(runResponse);
    mockRerunAllDiscoveryConfigs.mockResolvedValue([runResponse]);
    mockDeleteDiscoveryConfig.mockResolvedValue(undefined);
  });

  it("lets a deploy holder without certificate:issue trigger, rerun and rerun all", async () => {
    signInWith(DEPLOYER_PERMISSIONS);
    const trigger = renderHook(() => useTriggerDiscovery(), {
      wrapper: createWrapper(),
    });
    const rerun = renderHook(() => useRerunDiscoveryConfig(), {
      wrapper: createWrapper(),
    });
    const rerunAll = renderHook(() => useRerunAllDiscoveryConfigs(), {
      wrapper: createWrapper(),
    });

    await trigger.result.current.mutateAsync({
      credentialXref: "cred-1",
      targetType: "KUBERNETES",
    });
    await rerun.result.current.mutateAsync(7);
    await rerunAll.result.current.mutateAsync();

    expect(mockTriggerDiscovery).toHaveBeenCalledWith("KUBERNETES", "cred-1");
    expect(mockRerunDiscoveryConfig).toHaveBeenCalledWith(7);
    expect(mockRerunAllDiscoveryConfigs).toHaveBeenCalledTimes(1);
  });

  it("blocks triggers for an issuer without certificate:deploy", async () => {
    signInWith([PERMISSIONS.certificatesView, PERMISSIONS.certificatesCreate]);
    const trigger = renderHook(() => useTriggerDiscovery(), {
      wrapper: createWrapper(),
    });
    const rerun = renderHook(() => useRerunDiscoveryConfig(), {
      wrapper: createWrapper(),
    });
    const rerunAll = renderHook(() => useRerunAllDiscoveryConfigs(), {
      wrapper: createWrapper(),
    });

    await expect(
      trigger.result.current.mutateAsync({
        credentialXref: "cred-1",
        targetType: "KUBERNETES",
      }),
    ).rejects.toThrow("You do not have permission to trigger discovery");
    await expect(rerun.result.current.mutateAsync(7)).rejects.toThrow(
      "You do not have permission to run discovery",
    );
    await expect(rerunAll.result.current.mutateAsync()).rejects.toThrow(
      "You do not have permission to run discovery",
    );
    expect(mockTriggerDiscovery).not.toHaveBeenCalled();
    expect(mockRerunDiscoveryConfig).not.toHaveBeenCalled();
    expect(mockRerunAllDiscoveryConfigs).not.toHaveBeenCalled();
  });

  it("keeps deleting a discovery config on certificate:delete", async () => {
    signInWith(DEPLOYER_PERMISSIONS);
    const remove = renderHook(() => useDeleteDiscoveryConfig(), {
      wrapper: createWrapper(),
    });

    await expect(remove.result.current.mutateAsync(7)).rejects.toThrow(
      "You do not have permission to delete discovery configs",
    );
    expect(mockDeleteDiscoveryConfig).not.toHaveBeenCalled();

    signInWith([...DEPLOYER_PERMISSIONS, PERMISSIONS.certificatesDelete]);
    await remove.result.current.mutateAsync(7);
    expect(mockDeleteDiscoveryConfig).toHaveBeenCalledWith(7);
  });
});
