// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: { get: jest.fn(), post: jest.fn() },
  };
});

import { apiClient, apiRoutes } from "@/lib/api";
import {
  createDeployment,
  getDeploymentByRequestId,
  getDeploymentCredentialConfig,
  getDeploymentSummary,
  listAllDeployments,
  listAllUserDomainCertificateDeploymentSummaries,
  queryDeployments,
  queryUserDomainCertificateDeploymentSummaries,
} from "@/lib/backend/deployments";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
};

const deploymentRecord = (overrides: Record<string, unknown> = {}) => ({
  id: 1,
  requestId: "req-1",
  correlationId: "corr-1",
  organizationId: 42,
  userDomainCertId: 7,
  certificateXref: "cert-1",
  domain: "example.com",
  deploymentCredentialXref: "cred-1",
  targetType: "AZURE_KV",
  flowType: "MANUAL",
  status: "SUCCESS",
  wildcard: false,
  san: false,
  sanDomains: [],
  validFrom: "2026-07-01T00:00:00Z",
  validTo: "2026-10-01T00:00:00Z",
  issuer: "Example CA",
  serialNumber: "1234",
  fingerprintSha256: "AA:BB",
  targetResourceId: null,
  requestedAt: "2026-07-01T00:00:00Z",
  publishedAt: "2026-07-01T00:00:01Z",
  respondedAt: "2026-07-01T00:00:02Z",
  completedAt: "2026-07-01T00:00:03Z",
  source: "certping-agent",
  metadata: { triggeredBy: "manual" },
  createdAt: "2026-07-01T00:00:00Z",
  updatedAt: "2026-07-01T00:00:03Z",
  ...overrides,
});

const deploymentPage = (
  items: Array<Record<string, unknown>>,
  page = 0,
  totalPages = 1,
) => ({
  mode: "list",
  items,
  page,
  size: 100,
  totalItems: items.length * totalPages,
  totalPages,
});

describe("deployments adapter", () => {
  beforeEach(() => jest.clearAllMocks());

  it("maps the typed list response and query filters", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: deploymentPage([deploymentRecord()]),
    });

    const result = await queryDeployments({
      userDomainCertificateId: "7",
      status: "SUCCESS",
    });

    expect(result.items[0]).toEqual(
      expect.objectContaining({
        id: 1,
        organizationId: 42,
        domain: "example.com",
        status: "SUCCESS",
      }),
    );
    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.deployment.list,
      {
        params: { userdomaincertificateid: "7", status: "SUCCESS" },
      },
    );
  });

  it("maps the backend single mode used for request ID lookup", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: { mode: "single", item: deploymentRecord() },
    });

    await expect(getDeploymentByRequestId("req-1")).resolves.toEqual(
      expect.objectContaining({ id: 1, requestId: "req-1" }),
    );
  });

  it("uses the aggregate summary mode without downloading list pages", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        mode: "summary",
        summary: {
          total: 25,
          success: 20,
          failed: 2,
          publishFailed: 1,
          inProgress: 2,
        },
      },
    });

    await expect(getDeploymentSummary()).resolves.toEqual({
      total: 25,
      success: 20,
      failed: 2,
      publishFailed: 1,
      inProgress: 2,
    });
    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.deployment.list,
      { params: { view: "summary" } },
    );
  });

  it("loads remaining deployment pages in order", async () => {
    mockedApiClient.get
      .mockResolvedValueOnce({
        data: deploymentPage([deploymentRecord()], 0, 2),
      })
      .mockResolvedValueOnce({
        data: deploymentPage([deploymentRecord({ id: 2 })], 1, 2),
      });

    const result = await listAllDeployments({ size: 100 });
    expect(result.map(({ id }) => id)).toEqual([1, 2]);
    expect(mockedApiClient.get).toHaveBeenCalledTimes(2);
  });

  it("returns user-domain deployment summary pages directly", async () => {
    const page = {
      items: [
        {
          userDomainCertId: 7,
          domain: "example.com",
          deploymentsRequested: 3,
          deploymentsSucceeded: 2,
          deploymentsFailed: 1,
        },
      ],
      page: 0,
      size: 100,
      totalItems: 1,
      totalPages: 1,
    };
    mockedApiClient.get.mockResolvedValue({ data: page });

    await expect(
      queryUserDomainCertificateDeploymentSummaries({ domain: "example.com" }),
    ).resolves.toBe(page);
    await expect(
      listAllUserDomainCertificateDeploymentSummaries({
        domain: "example.com",
      }),
    ).resolves.toEqual(page.items);
  });

  it("posts the typed deployment request", async () => {
    mockedApiClient.post.mockResolvedValue({
      data: {
        certificateXref: "cert-1",
        domain: "example.com",
        status: "DEPLOYING",
        submittedAt: "2026-07-01T00:00:00Z",
      },
    });

    await expect(
      createDeployment({
        certificateXref: "cert-1",
        deploymentCredentialXref: "cred-1",
        targetType: "AZURE_KV",
      }),
    ).resolves.toEqual(expect.objectContaining({ status: "DEPLOYING" }));
    expect(mockedApiClient.post).toHaveBeenCalledWith(
      apiRoutes.mutation.certs.deploy("cert-1"),
      {
        deploymentCredentialXref: "cred-1",
        targetType: "AZURE_KV",
      },
    );
  });

  it("parses the credential config JSON at its actual trust boundary", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        certXref: "cert-1",
        domain: "example.com",
        organizationId: 42,
        userDomainCertId: 7,
        deploymentCredentialXref: "cred-1",
        deploymentCredentialId: 9,
        provider: "KUBERNETES_SECRETS",
        config: '{"targets":{"namespace":"production"}}',
        createdAt: "2026-07-01T00:00:00Z",
        updatedAt: "2026-07-01T00:00:00Z",
      },
    });

    await expect(
      getDeploymentCredentialConfig("cert-1", "cred-1"),
    ).resolves.toEqual(
      expect.objectContaining({
        config: { targets: { namespace: "production" } },
        targets: null,
      }),
    );
  });
});
