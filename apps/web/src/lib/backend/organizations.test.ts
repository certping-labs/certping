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

import { apiClient, apiRoutes } from "@/lib/api";
import {
  createOrganization,
  deleteOrganization,
  getOrganizationById,
  getOrganizationBySlug,
  getOrganizationIdValue,
  listOrganizations,
  updateOrganization,
  getOrgRetentionSettings,
  setOrgRetentionSettings,
  purgeOrgSoftDeleted,
  getGlobalRetentionSettings,
  setGlobalRetentionSettings,
} from "@/lib/backend/organizations";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
  put: jest.Mock;
  delete: jest.Mock;
};

describe("organizations adapter", () => {
  beforeEach(() => {
    mockedApiClient.get.mockReset();
    mockedApiClient.post.mockReset();
    mockedApiClient.put.mockReset();
    mockedApiClient.delete.mockReset();
  });

  it("returns the numeric organization ID as a route value", () => {
    expect(getOrganizationIdValue({ id: 7 } as never)).toBe("7");
  });

  it("returns the typed organization list", async () => {
    const payload = [
      {
        id: 7,
        name: "Tenant Alpha",
        slug: "tenant-alpha",
        active: false,
        agentHeartbeatCadenceMinutes: 5,
      },
      {
        id: 12,
        name: "Org 12",
        slug: "org-12",
        domain: "org12.example.com",
        active: true,
      },
    ];
    mockedApiClient.get.mockResolvedValue({
      data: payload,
    });

    const organizations = await listOrganizations();

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.organization.list,
    );
    expect(organizations).toBe(payload);
  });

  it("gets organizations by id and slug", async () => {
    mockedApiClient.get
      .mockResolvedValueOnce({
        data: {
          id: 20,
          name: "Tenant Twenty",
          slug: "tenant-twenty",
        },
      })
      .mockResolvedValueOnce({
        data: {
          id: 21,
          name: "Org Twenty One",
          slug: "twenty-one",
        },
      });

    const byId = await getOrganizationById("20");
    const bySlug = await getOrganizationBySlug("twenty-one");

    expect(byId).toEqual(
      expect.objectContaining({
        id: 20,
        name: "Tenant Twenty",
        slug: "tenant-twenty",
      }),
    );
    expect(bySlug).toEqual(
      expect.objectContaining({
        id: 21,
        name: "Org Twenty One",
      }),
    );
  });

  it("creates and updates organizations", async () => {
    mockedApiClient.post.mockResolvedValueOnce({
      data: { id: 9, name: "Created Org", domain: "created.example.com" },
    });
    mockedApiClient.put.mockResolvedValueOnce({
      data: {
        id: 9,
        name: "Updated Org",
        domain: "updated.example.com",
        active: true,
      },
    });

    const createPayload = {
      name: "Created Org",
      domain: "created.example.com",
    };
    const created = await createOrganization(createPayload);
    const updated = await updateOrganization("9", {
      name: "Updated Org",
      domain: "updated.example.com",
      active: true,
    });

    expect(mockedApiClient.post).toHaveBeenCalledWith(
      apiRoutes.mutation.organization.create,
      createPayload,
    );
    expect(mockedApiClient.put).toHaveBeenCalledWith(
      apiRoutes.mutation.organization.update("9"),
      {
        name: "Updated Org",
        domain: "updated.example.com",
        active: true,
      },
    );
    expect(created.name).toBe("Created Org");
    expect(updated.name).toBe("Updated Org");
  });

  it("passes through delete organization message response", async () => {
    mockedApiClient.delete.mockResolvedValueOnce({
      data: { message: "Deleted successfully" },
    });

    await expect(deleteOrganization("15")).resolves.toEqual({
      message: "Deleted successfully",
    });
    expect(mockedApiClient.delete).toHaveBeenCalledWith(
      apiRoutes.mutation.organization.delete("15"),
    );
  });
});

describe("organizations – data retention", () => {
  beforeEach(() => {
    mockedApiClient.get.mockReset();
    mockedApiClient.post.mockReset();
    mockedApiClient.put.mockReset();
  });

  describe("getOrgRetentionSettings", () => {
    it("parses normal numeric values correctly", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: { overrideDays: 30, effectiveDays: 30, globalDays: 90 },
      });

      const result = await getOrgRetentionSettings("org-1");

      expect(result).toEqual({
        overrideDays: 30,
        effectiveDays: 30,
        globalDays: 90,
      });
    });

    it('treats the string "null" as a null overrideDays (org inherits global)', async () => {
      mockedApiClient.get.mockResolvedValue({
        data: { overrideDays: "null", effectiveDays: 90, globalDays: 90 },
      });

      const result = await getOrgRetentionSettings("org-1");

      expect(result.overrideDays).toBeNull();
      expect(result.effectiveDays).toBe(90);
      expect(result.globalDays).toBe(90);
    });

    it("preserves numeric retention values", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: { overrideDays: 60, effectiveDays: 60, globalDays: 120 },
      });

      const result = await getOrgRetentionSettings(42);

      expect(result).toEqual({
        overrideDays: 60,
        effectiveDays: 60,
        globalDays: 120,
      });
    });
  });

  describe("setOrgRetentionSettings", () => {
    it("sends the days value when a number is provided", async () => {
      mockedApiClient.put.mockResolvedValue({ data: {} });

      await setOrgRetentionSettings("org-1", 45);

      expect(mockedApiClient.put).toHaveBeenCalledWith(expect.any(String), {
        days: 45,
      });
    });

    it('sends the string "null" when days is null (removes org override)', async () => {
      mockedApiClient.put.mockResolvedValue({ data: {} });

      await setOrgRetentionSettings("org-1", null);

      expect(mockedApiClient.put).toHaveBeenCalledWith(expect.any(String), {
        days: "null",
      });
    });
  });

  describe("purgeOrgSoftDeleted", () => {
    it("POSTs to the purge endpoint and returns the response payload", async () => {
      mockedApiClient.post.mockResolvedValue({
        data: { totalHardDeleted: 12 },
      });

      const result = await purgeOrgSoftDeleted("org-1");

      expect(mockedApiClient.post).toHaveBeenCalledWith(expect.any(String));
      expect(result).toEqual({ totalHardDeleted: 12 });
    });
  });

  describe("getGlobalRetentionSettings", () => {
    it("returns the global retention days from the admin endpoint", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: { globalRetentionDays: 365 },
      });

      const result = await getGlobalRetentionSettings();

      expect(result).toEqual({ globalRetentionDays: 365 });
    });
  });

  describe("setGlobalRetentionSettings", () => {
    it("PUTs the days value to the admin endpoint", async () => {
      mockedApiClient.put.mockResolvedValue({ data: {} });

      await setGlobalRetentionSettings(180);

      expect(mockedApiClient.put).toHaveBeenCalledWith(expect.any(String), {
        days: 180,
      });
    });
  });
});
