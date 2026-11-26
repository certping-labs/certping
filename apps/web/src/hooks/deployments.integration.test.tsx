// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import {
  useAllDeployments,
  useDeployCertificate,
  useDeploymentByRequestId,
  useDeploymentCredentialConfig,
  useDeploymentCredentialReference,
  useDeploymentLiveCertificate,
  useDeployments,
  useUserDomainCertificateDeploymentSummaries,
} from "@/hooks/deployments";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";

const queryDeploymentsMock = jest.fn();
const listAllDeploymentsMock = jest.fn();
const querySummariesMock = jest.fn();
const getDeploymentByRequestIdMock = jest.fn();
const getCertificateDetailMock = jest.fn();
const getCredentialReferenceMock = jest.fn();
const getDeploymentCredentialConfigMock = jest.fn();
const createDeploymentMock = jest.fn();
const invalidateDeploymentQueriesMock = jest.fn();
const invalidateCertificateQueriesMock = jest.fn();
const invalidateCredentialQueriesMock = jest.fn();
const invalidateAlertQueriesMock = jest.fn();
const invalidateAuditQueriesMock = jest.fn();

jest.mock("sonner", () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

jest.mock("@/lib/backend/deployments", () => ({
  createDeployment: (...args: unknown[]) => createDeploymentMock(...args),
  getDeploymentCredentialConfig: (...args: unknown[]) =>
    getDeploymentCredentialConfigMock(...args),
  getDeploymentByRequestId: (...args: unknown[]) =>
    getDeploymentByRequestIdMock(...args),
  listAllDeployments: (...args: unknown[]) => listAllDeploymentsMock(...args),
  listAllUserDomainCertificateDeploymentSummaries: (...args: unknown[]) =>
    listAllDeploymentsMock(...args),
  queryUserDomainCertificateDeploymentSummaries: (...args: unknown[]) =>
    querySummariesMock(...args),
  queryDeployments: (...args: unknown[]) => queryDeploymentsMock(...args),
}));

jest.mock("@/lib/backend/certs", () => ({
  getCertificateDetail: (...args: unknown[]) =>
    getCertificateDetailMock(...args),
}));

jest.mock("@/lib/backend/credentials", () => ({
  getCredentialReference: (...args: unknown[]) =>
    getCredentialReferenceMock(...args),
}));

jest.mock("@/hooks/query-invalidation", () => ({
  invalidateAlertQueries: (...args: unknown[]) =>
    invalidateAlertQueriesMock(...args),
  invalidateAuditQueries: (...args: unknown[]) =>
    invalidateAuditQueriesMock(...args),
  invalidateCertificateQueries: (...args: unknown[]) =>
    invalidateCertificateQueriesMock(...args),
  invalidateCredentialQueries: (...args: unknown[]) =>
    invalidateCredentialQueriesMock(...args),
  invalidateDeploymentQueries: (...args: unknown[]) =>
    invalidateDeploymentQueriesMock(...args),
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

describe("deployments hooks integration", () => {
  beforeEach(() => {
    queryDeploymentsMock.mockReset();
    listAllDeploymentsMock.mockReset();
    querySummariesMock.mockReset();
    getDeploymentByRequestIdMock.mockReset();
    getCertificateDetailMock.mockReset();
    getCredentialReferenceMock.mockReset();
    getDeploymentCredentialConfigMock.mockReset();
    createDeploymentMock.mockReset();
    invalidateDeploymentQueriesMock.mockResolvedValue(undefined);
    invalidateCertificateQueriesMock.mockResolvedValue(undefined);
    invalidateCredentialQueriesMock.mockResolvedValue(undefined);
    invalidateAlertQueriesMock.mockResolvedValue(undefined);
    invalidateAuditQueriesMock.mockResolvedValue(undefined);

    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["deployments:view", "certificate:deploy"],
        authMethod: "LOCAL",
      },
      isLoading: false,
      isSuperAdmin: false,
      expiresAt: Date.now() + 60_000,
    });
    useFeatureFlagStore
      .getState()
      .setEffectiveMap({ CERTIFICATE_DEPLOYMENT: true });
  });

  it("loads deployment query collections", async () => {
    queryDeploymentsMock.mockResolvedValue({ items: [], totalItems: 0 });
    listAllDeploymentsMock.mockResolvedValue([
      { requestId: "req-1", domain: "alpha.example.com" },
    ]);
    querySummariesMock.mockResolvedValue({ items: [], totalItems: 0 });

    const deployments = renderHook(
      () => useDeployments({ status: "SUCCESS" }),
      {
        wrapper: createWrapper(),
      },
    );
    const allDeployments = renderHook(() => useAllDeployments(), {
      wrapper: createWrapper(),
    });
    const summaries = renderHook(
      () => useUserDomainCertificateDeploymentSummaries({ page: 0, size: 10 }),
      { wrapper: createWrapper() },
    );

    await waitFor(() => {
      expect(deployments.result.current.isSuccess).toBe(true);
      expect(allDeployments.result.current.isSuccess).toBe(true);
      expect(summaries.result.current.isSuccess).toBe(true);
    });
  });

  it("polls deployment lists while deployment records are in progress", async () => {
    jest.useFakeTimers();
    queryDeploymentsMock
      .mockResolvedValueOnce({
        items: [{ id: "dep-1", requestId: "req-1", status: "DEPLOYING" }],
        totalItems: 1,
      })
      .mockResolvedValue({
        items: [{ id: "dep-1", requestId: "req-1", status: "SUCCESS" }],
        totalItems: 1,
      });

    try {
      const deployments = renderHook(() => useDeployments(), {
        wrapper: createWrapper(),
      });

      await waitFor(() =>
        expect(deployments.result.current.isSuccess).toBe(true),
      );
      expect(queryDeploymentsMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        jest.advanceTimersByTime(5_000);
      });

      await waitFor(() => {
        expect(queryDeploymentsMock).toHaveBeenCalledTimes(2);
      });

      await act(async () => {
        jest.advanceTimersByTime(5_000);
      });

      expect(queryDeploymentsMock).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it("polls deployment summaries while requested deployments are unresolved", async () => {
    jest.useFakeTimers();
    querySummariesMock
      .mockResolvedValueOnce({
        items: [
          {
            userDomainCertId: 101,
            domain: "alpha.example.com",
            deploymentsRequested: 2,
            deploymentsSucceeded: 1,
            deploymentsFailed: 0,
          },
        ],
        totalItems: 1,
      })
      .mockResolvedValue({
        items: [
          {
            userDomainCertId: 101,
            domain: "alpha.example.com",
            deploymentsRequested: 2,
            deploymentsSucceeded: 2,
            deploymentsFailed: 0,
          },
        ],
        totalItems: 1,
      });

    try {
      const summaries = renderHook(
        () => useUserDomainCertificateDeploymentSummaries(),
        {
          wrapper: createWrapper(),
        },
      );

      await waitFor(() =>
        expect(summaries.result.current.isSuccess).toBe(true),
      );
      expect(querySummariesMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        jest.advanceTimersByTime(5_000);
      });

      await waitFor(() => {
        expect(querySummariesMock).toHaveBeenCalledTimes(2);
      });

      await act(async () => {
        jest.advanceTimersByTime(5_000);
      });

      expect(querySummariesMock).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it("disables deployment queries when user lacks view permission", async () => {
    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: [],
        authMethod: "LOCAL",
      },
      isLoading: false,
      isSuperAdmin: false,
      expiresAt: Date.now() + 60_000,
    });

    queryDeploymentsMock.mockResolvedValue({ items: [], totalItems: 0 });

    const deployments = renderHook(() => useDeployments(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => {
      expect(deployments.result.current.fetchStatus).toBe("idle");
    });
    expect(queryDeploymentsMock).not.toHaveBeenCalled();
  });

  it("disables deployment queries when certificate deployment flag is off", async () => {
    useFeatureFlagStore
      .getState()
      .setEffectiveMap({ CERTIFICATE_DEPLOYMENT: false });
    queryDeploymentsMock.mockResolvedValue({ items: [], totalItems: 0 });
    listAllDeploymentsMock.mockResolvedValue([]);
    querySummariesMock.mockResolvedValue({ items: [], totalItems: 0 });

    const deployments = renderHook(() => useDeployments(), {
      wrapper: createWrapper(),
    });
    const allDeployments = renderHook(() => useAllDeployments(), {
      wrapper: createWrapper(),
    });
    const summaries = renderHook(
      () => useUserDomainCertificateDeploymentSummaries(),
      { wrapper: createWrapper() },
    );

    await waitFor(() => {
      expect(deployments.result.current.fetchStatus).toBe("idle");
      expect(allDeployments.result.current.fetchStatus).toBe("idle");
      expect(summaries.result.current.fetchStatus).toBe("idle");
    });

    expect(queryDeploymentsMock).not.toHaveBeenCalled();
    expect(listAllDeploymentsMock).not.toHaveBeenCalled();
    expect(querySummariesMock).not.toHaveBeenCalled();
  });

  it("loads single deployment, certificate, credential and config lookups", async () => {
    getDeploymentByRequestIdMock.mockResolvedValue({
      requestId: "req-1",
      certificateXref: "cert-1",
      deploymentCredentialXref: "cred-1",
    });
    getCertificateDetailMock.mockResolvedValue({
      certificateXref: "cert-1",
      domain: "alpha.example.com",
      status: "ACTIVE",
    });
    getCredentialReferenceMock.mockResolvedValue({
      credentialXref: "cred-1",
      provider: "AKAMAI_CPS",
      type: "DEPLOYMENT",
    });
    getDeploymentCredentialConfigMock.mockResolvedValue({
      certXref: "cert-1",
      deploymentCredentialXref: "cred-1",
      deploymentCredentialSummary: "ready",
    });

    const request = renderHook(() => useDeploymentByRequestId("req-1"), {
      wrapper: createWrapper(),
    });
    const cert = renderHook(() => useDeploymentLiveCertificate("cert-1"), {
      wrapper: createWrapper(),
    });
    const cred = renderHook(() => useDeploymentCredentialReference("cred-1"), {
      wrapper: createWrapper(),
    });
    const config = renderHook(
      () => useDeploymentCredentialConfig("cert-1", "cred-1"),
      { wrapper: createWrapper() },
    );

    await waitFor(() => {
      expect(request.result.current.isSuccess).toBe(true);
      expect(cert.result.current.isSuccess).toBe(true);
      expect(cred.result.current.isSuccess).toBe(true);
      expect(config.result.current.isSuccess).toBe(true);
    });
  });

  it("polls a single deployment request while it is in progress", async () => {
    jest.useFakeTimers();
    getDeploymentByRequestIdMock
      .mockResolvedValueOnce({
        id: "dep-1",
        requestId: "req-1",
        status: "IN_PROGRESS",
      })
      .mockResolvedValue({
        id: "dep-1",
        requestId: "req-1",
        status: "SUCCESS",
      });

    try {
      const request = renderHook(() => useDeploymentByRequestId("req-1"), {
        wrapper: createWrapper(),
      });

      await waitFor(() => expect(request.result.current.isSuccess).toBe(true));
      expect(getDeploymentByRequestIdMock).toHaveBeenCalledTimes(1);

      await act(async () => {
        jest.advanceTimersByTime(5_000);
      });

      await waitFor(() => {
        expect(getDeploymentByRequestIdMock).toHaveBeenCalledTimes(2);
      });

      await act(async () => {
        jest.advanceTimersByTime(5_000);
      });

      expect(getDeploymentByRequestIdMock).toHaveBeenCalledTimes(2);
    } finally {
      jest.useRealTimers();
    }
  });

  it("skips request-id and credential-config queries when inputs are empty", async () => {
    getDeploymentByRequestIdMock.mockResolvedValue(null);
    getDeploymentCredentialConfigMock.mockResolvedValue({
      certXref: "cert-1",
      deploymentCredentialXref: "cred-1",
      deploymentCredentialSummary: "ready",
    });

    const request = renderHook(() => useDeploymentByRequestId(""), {
      wrapper: createWrapper(),
    });
    const config = renderHook(
      () => useDeploymentCredentialConfig("cert-1", ""),
      {
        wrapper: createWrapper(),
      },
    );

    await waitFor(() => {
      expect(request.result.current.fetchStatus).toBe("idle");
      expect(config.result.current.fetchStatus).toBe("idle");
    });

    expect(getDeploymentByRequestIdMock).not.toHaveBeenCalled();
    expect(getDeploymentCredentialConfigMock).not.toHaveBeenCalled();
  });

  it("creates deployment and invalidates related query groups", async () => {
    createDeploymentMock.mockResolvedValue({
      requestId: "req-new",
      domain: "beta.example.com",
      status: "PENDING",
    });

    const hook = renderHook(() => useDeployCertificate(), {
      wrapper: createWrapper(),
    });

    await hook.result.current.mutateAsync({
      certificateXref: "cert-1",
      deploymentCredentialXref: "cred-1",
      targetType: "AKAMAI",
    });

    expect(invalidateDeploymentQueriesMock).toHaveBeenCalled();
    expect(invalidateCertificateQueriesMock).toHaveBeenCalled();
    expect(invalidateCredentialQueriesMock).toHaveBeenCalled();
    expect(invalidateAlertQueriesMock).toHaveBeenCalled();
    expect(invalidateAuditQueriesMock).toHaveBeenCalled();
  });

  it("fails mutation when user lacks deploy permission", async () => {
    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["deployments:view"],
        authMethod: "LOCAL",
      },
      isLoading: false,
      isSuperAdmin: false,
      expiresAt: Date.now() + 60_000,
    });

    const hook = renderHook(() => useDeployCertificate(), {
      wrapper: createWrapper(),
    });

    await expect(
      hook.result.current.mutateAsync({
        certificateXref: "cert-1",
        deploymentCredentialXref: "cred-1",
        targetType: "AKAMAI",
      }),
    ).rejects.toThrow("You do not have permission to create deployments");
  });

  it("fails mutation when certificate deployment flag is off", async () => {
    useFeatureFlagStore
      .getState()
      .setEffectiveMap({ CERTIFICATE_DEPLOYMENT: false });

    const hook = renderHook(() => useDeployCertificate(), {
      wrapper: createWrapper(),
    });

    await expect(
      hook.result.current.mutateAsync({
        certificateXref: "cert-1",
        deploymentCredentialXref: "cred-1",
        targetType: "AKAMAI",
      }),
    ).rejects.toThrow(
      "Certificate deployment isn't available. Ask your CertPing administrator.",
    );
    expect(createDeploymentMock).not.toHaveBeenCalled();
  });
});
