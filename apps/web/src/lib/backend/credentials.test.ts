// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    },
  };
});

import { apiClient } from "@/lib/api";
import {
  createDeploymentCredentialReference,
  createDnsCredentialReference,
  deleteCredentialReference,
  getCredentialReference,
  listCredentialReferences,
  updateCredentialReference,
} from "@/lib/backend/credentials";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
  put: jest.Mock;
  delete: jest.Mock;
};

describe("credentials adapter", () => {
  beforeEach(() => {
    mockedApiClient.get.mockReset();
    mockedApiClient.post.mockReset();
    mockedApiClient.put.mockReset();
    mockedApiClient.delete.mockReset();
  });

  it("normalizes credential references from the list API", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [
          {
            credentialXref: "cred_dns_123",
            provider: "CLOUDFLARE",
            type: "DNS",
            description: "Primary DNS credential",
            status: "ACTIVE",
            secretHandle: "https://kv.example.net/secrets/dns-cred-1",
            createdAt: "2026-04-06T12:00:00Z",
            updatedAt: "2026-04-06T12:30:00Z",
          },
        ],
        totalItems: 1,
      },
    });

    const result = await listCredentialReferences("DNS");

    expect(result).toEqual({
      items: [
        expect.objectContaining({
          credentialXref: "cred_dns_123",
          provider: "CLOUDFLARE",
          providerKey: "cloudflare",
          type: "DNS",
          description: "Primary DNS credential",
          secretHandle: "https://kv.example.net/secrets/dns-cred-1",
        }),
      ],
      totalItems: 1,
    });
  });

  it("posts DNS credential references to the documented endpoint", async () => {
    mockedApiClient.post.mockResolvedValue({
      data: {
        credentialXref: "cred_dns_456",
        provider: "CLOUDFLARE",
        type: "DNS",
        description: "Edge DNS credential",
        status: "ACTIVE",
      },
    });

    const result = await createDnsCredentialReference({
      provider: "CLOUDFLARE",
      description: "Edge DNS credential",
      secretHandle: "https://kv.example.net/secrets/cloudflare-dns",
    });

    expect(mockedApiClient.post).toHaveBeenCalledWith(
      "/api/v1/credentials/dns",
      {
        provider: "CLOUDFLARE",
        description: "Edge DNS credential",
        secretHandle: "https://kv.example.net/secrets/cloudflare-dns",
      },
    );
    expect(result.credentialXref).toBe("cred_dns_456");
    expect(result.providerKey).toBe("cloudflare");
  });

  it("passes stored credJson payloads through unchanged", async () => {
    mockedApiClient.post.mockResolvedValue({
      data: {
        credentialXref: "cred_dns_managed_1",
        provider: "CLOUDFLARE",
        type: "DNS",
        description: "Stored Cloudflare DNS",
        status: "ACTIVE",
      },
    });

    await createDnsCredentialReference({
      provider: "CLOUDFLARE",
      description: "Stored Cloudflare DNS",
      credJson: {
        apiToken: "cf-xxx",
      },
    });

    expect(mockedApiClient.post).toHaveBeenCalledWith(
      "/api/v1/credentials/dns",
      {
        provider: "CLOUDFLARE",
        description: "Stored Cloudflare DNS",
        credJson: {
          apiToken: "cf-xxx",
        },
      },
    );
  });

  it("supports get, deployment create, update and delete flows", async () => {
    mockedApiClient.get.mockResolvedValueOnce({
      data: {
        credentialXref: "cred_deploy_1",
        provider: "AWS_ACM",
        type: "DEPLOYMENT",
        description: "Deployment credential",
        status: "ACTIVE",
      },
    });
    mockedApiClient.post.mockResolvedValueOnce({
      data: {
        credentialXref: "cred_deploy_1",
        provider: "AWS_ACM",
        type: "DEPLOYMENT",
        description: "Deployment credential",
        status: "ACTIVE",
      },
    });
    mockedApiClient.put.mockResolvedValueOnce({
      data: {
        credentialXref: "cred_deploy_1",
        provider: "AWS_ACM",
        type: "DEPLOYMENT",
        status: "ACTIVE",
        updatedAt: "2026-07-22T10:00:00Z",
        message: "Credential scope updated.",
      },
    });
    mockedApiClient.delete.mockResolvedValueOnce({
      data: {
        credentialXref: "cred_deploy_1",
        status: "DELETED",
        deletedAt: "2026-07-22T10:01:00Z",
        message: "Credential reference deleted.",
      },
    });

    await expect(getCredentialReference("cred_deploy_1")).resolves.toEqual(
      expect.objectContaining({
        credentialXref: "cred_deploy_1",
        providerKey: "aws",
      }),
    );

    await expect(
      createDeploymentCredentialReference({
        provider: "AWS_ACM",
        description: "Deployment credential",
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        credentialXref: "cred_deploy_1",
        type: "DEPLOYMENT",
      }),
    );

    await expect(
      updateCredentialReference("cred_deploy_1", {
        secretHandle: "https://kv/cred",
        credJson: { username: "admin", password: "secret" },
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        message: "Credential scope updated.",
      }),
    );

    await expect(deleteCredentialReference("cred_deploy_1")).resolves.toEqual(
      expect.objectContaining({
        credentialXref: "cred_deploy_1",
      }),
    );
  });
});
