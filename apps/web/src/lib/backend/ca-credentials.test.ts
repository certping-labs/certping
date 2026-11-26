// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return { ...actual, apiClient: { get: jest.fn(), post: jest.fn() } };
});

import { apiClient } from "@/lib/api";
import {
  createCaCredential,
  listCaCredentials,
} from "@/lib/backend/ca-credentials";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
};

describe("CA credentials adapter", () => {
  beforeEach(() => {
    mockedApiClient.get.mockReset();
    mockedApiClient.post.mockReset();
  });

  it("lists only the provider's active CA credentials", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [
          {
            credentialXref: "ca-1",
            provider: "DIGICERT",
            description: "Main",
            status: "ACTIVE",
          },
          {
            credentialXref: "ca-2",
            provider: "DIGICERT",
            description: null,
            status: "ACTIVE",
          },
          {
            credentialXref: "ca-3",
            provider: "DIGICERT",
            description: "Old",
            status: "DELETED",
          },
          {
            credentialXref: "ca-4",
            provider: "GLOBALSIGN",
            description: "Other",
            status: "ACTIVE",
          },
        ],
      },
    });

    await expect(listCaCredentials("DIGICERT")).resolves.toEqual([
      { credentialXref: "ca-1", provider: "DIGICERT", description: "Main" },
      { credentialXref: "ca-2", provider: "DIGICERT", description: "ca-2" },
    ]);
    expect(mockedApiClient.get).toHaveBeenCalledWith("/api/v1/credentials", {
      params: { type: "CA" },
    });
  });

  it("sends the key as credJson and returns only the reference", async () => {
    mockedApiClient.post.mockResolvedValue({
      data: {
        credentialXref: "ca-9",
        provider: "DIGICERT",
        description: "Key",
        status: "ACTIVE",
      },
    });

    await expect(
      createCaCredential({
        provider: "DIGICERT",
        description: "Key",
        apiKey: "dc-secret",
      }),
    ).resolves.toEqual({
      credentialXref: "ca-9",
      provider: "DIGICERT",
      description: "Key",
    });
    expect(mockedApiClient.post).toHaveBeenCalledWith(
      "/api/v1/credentials/ca",
      {
        provider: "DIGICERT",
        description: "Key",
        credJson: { apiKey: "dc-secret" },
      },
    );
  });
});
