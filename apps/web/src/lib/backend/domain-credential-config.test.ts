// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      patch: jest.fn(),
      post: jest.fn(),
      delete: jest.fn(),
    },
  };
});

import { apiClient } from "@/lib/api";
import { syncCertificateCredentialConfig } from "@/lib/backend/domain-credential-config";

const mockedApiClient = apiClient as unknown as {
  patch: jest.Mock;
  post: jest.Mock;
  delete: jest.Mock;
};

describe("syncCertificateCredentialConfig", () => {
  beforeEach(() => {
    mockedApiClient.patch.mockReset();
    mockedApiClient.post.mockReset();
    mockedApiClient.delete.mockReset();
  });

  it("returns no changes and performs no API calls when config is unchanged", async () => {
    const result = await syncCertificateCredentialConfig({
      domain: "example.com",
      currentDnsConfigXref: "dns-1",
      dnsConfigXref: "dns-1",
      currentDeploymentCredentialXrefs: ["deploy-1"],
      deploymentCredentialXrefs: ["deploy-1"],
    });

    expect(mockedApiClient.patch).not.toHaveBeenCalled();
    expect(mockedApiClient.post).not.toHaveBeenCalled();
    expect(mockedApiClient.delete).not.toHaveBeenCalled();
    expect(result).toEqual({
      didChange: false,
      latestConfig: undefined,
      updatedDnsConfig: false,
      addedDeploymentTargets: [],
      removedDeploymentTargets: [],
    });
  });

  it("patches dns config only when the dns credential changes", async () => {
    mockedApiClient.patch.mockResolvedValue({
      data: {
        id: "config-1",
        userDomainCertId: "cert-1",
        dnsConfig: { "example.com": "dns-2" },
        deploymentTargets: [],
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
    });

    const result = await syncCertificateCredentialConfig({
      domain: "example.com",
      currentDnsConfigXref: "dns-1",
      dnsConfigXref: "dns-2",
      currentDeploymentCredentialXrefs: [],
      deploymentCredentialXrefs: [],
    });

    expect(mockedApiClient.patch).toHaveBeenCalledWith(
      "/api/v1/certs/domains/example.com/credential-config/dns",
      {
        targetDomain: "example.com",
        credentialXref: "dns-2",
      },
    );
    expect(result.updatedDnsConfig).toBe(true);
    expect(result.didChange).toBe(true);
  });

  it("removes targets before adding new ones and deduplicates incoming ids", async () => {
    mockedApiClient.delete.mockResolvedValueOnce({
      data: {
        id: "config-1",
        dnsConfig: {},
        deploymentTargets: ["deploy-2"],
      },
    });
    mockedApiClient.post.mockResolvedValueOnce({
      data: {
        id: "config-1",
        dnsConfig: {},
        deploymentTargets: ["deploy-2", "deploy-3"],
      },
    });

    const result = await syncCertificateCredentialConfig({
      domain: "example.com",
      currentDeploymentCredentialXrefs: ["deploy-1", "deploy-1", "deploy-2"],
      deploymentCredentialXrefs: ["deploy-2", "deploy-3", "deploy-3"],
    });

    expect(mockedApiClient.delete).toHaveBeenCalledTimes(1);
    expect(mockedApiClient.post).toHaveBeenCalledTimes(1);
    expect(mockedApiClient.delete.mock.invocationCallOrder[0]).toBeLessThan(
      mockedApiClient.post.mock.invocationCallOrder[0],
    );
    expect(result).toEqual(
      expect.objectContaining({
        didChange: true,
        updatedDnsConfig: false,
        addedDeploymentTargets: ["deploy-3"],
        removedDeploymentTargets: ["deploy-1"],
      }),
    );
  });

  it("posts kubernetes deployment config when provided", async () => {
    mockedApiClient.post.mockResolvedValueOnce({
      data: {
        id: "config-1",
        dnsConfig: {},
        deploymentTargets: ["k8s-1"],
      },
    });

    await syncCertificateCredentialConfig({
      domain: "example.com",
      currentDeploymentCredentialXrefs: [],
      deploymentCredentialXrefs: ["k8s-1"],
      deploymentTargetConfigs: [
        {
          credentialXref: "k8s-1",
          config: {
            useDefault: false,
            nsSecretMap: [{ "app-prod": "tls-example-com" }],
          },
        },
      ],
    });

    expect(mockedApiClient.post).toHaveBeenCalledWith(
      "/api/v1/certs/domains/example.com/credential-config/deployment-targets",
      {
        credentialXref: "k8s-1",
        config: {
          useDefault: false,
          nsSecretMap: [{ "app-prod": "tls-example-com" }],
        },
      },
    );
  });
});
