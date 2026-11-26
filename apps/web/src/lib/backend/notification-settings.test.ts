// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient } from "@/lib/api";
import {
  getNotificationSettings,
  saveNotificationSettings,
} from "@/lib/backend/notification-settings";

jest.mock("@/lib/api", () => ({
  apiClient: { get: jest.fn(), put: jest.fn() },
  apiRoutes: {
    query: {
      organization: {
        notificationSettings: (orgId: string | number) =>
          `/api/v1/organizations/${orgId}/settings/notifications`,
      },
    },
    mutation: {
      organization: {
        notificationSettings: (orgId: string | number) =>
          `/api/v1/organizations/${orgId}/settings/notifications`,
      },
    },
  },
}));

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
  put: jest.Mock;
};
const mockedGet = mockedApiClient.get;
const mockedPut = mockedApiClient.put;

const CATEGORIES = [
  { key: "CERTIFICATE_ACTIVITY", enabled: false },
  { key: "REPORTS", enabled: true },
];

describe("notification settings backend", () => {
  beforeEach(() => jest.clearAllMocks());

  it("reads the organization's categories", async () => {
    mockedGet.mockResolvedValue({ data: { categories: CATEGORIES } });

    await expect(getNotificationSettings("7")).resolves.toEqual(CATEGORIES);
    expect(mockedGet).toHaveBeenCalledWith(
      "/api/v1/organizations/7/settings/notifications",
    );
  });

  it("saves the complete list of categories turned off", async () => {
    mockedPut.mockResolvedValue({ data: { categories: CATEGORIES } });

    await expect(
      saveNotificationSettings(7, ["CERTIFICATE_ACTIVITY"]),
    ).resolves.toEqual(CATEGORIES);
    expect(mockedPut).toHaveBeenCalledWith(
      "/api/v1/organizations/7/settings/notifications",
      { muted: ["CERTIFICATE_ACTIVITY"] },
    );
  });

  it("refuses an answer it cannot read", async () => {
    mockedGet.mockResolvedValue({ data: { categories: [{ key: "" }] } });

    await expect(getNotificationSettings("7")).rejects.toThrow();
  });
});
