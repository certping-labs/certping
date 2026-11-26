// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      get: jest.fn(),
    },
  };
});

import { apiClient, apiRoutes } from "@/lib/api";
import { getSystemNotifications } from "@/lib/backend/notifications";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
};

describe("notifications adapter", () => {
  beforeEach(() => {
    mockedApiClient.get.mockReset();
  });

  it("should request and normalize the default paginated response", async () => {
    mockedApiClient.get.mockResolvedValueOnce({
      data: {
        success: true,
        data: [
          {
            id: 12345,
            organizationId: 42,
            userId: 7,
            requestId: "req-mark-expired-certs-1",
            notificationType: "CERT_EXPIRED",
            notificationAction: "EXPIRE",
            status: "DELIVERED",
            recipients: ["ops@example.com", "security@example.com"],
            roles: ["ORGANIZATION_ADMIN"],
            source: "CERTIFICATE_SCHEDULER",
            createdAt: "2026-07-21T09:12:44Z",
          },
        ],
        page: 0,
        size: 20,
        totalElements: 4231,
        totalPages: 212,
      },
    });

    const result = await getSystemNotifications();

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.incidents.notifications,
      { params: { page: 0, size: 20 } },
    );
    expect(result).toEqual({
      page: 0,
      size: 20,
      totalElements: 4231,
      totalPages: 212,
      items: [
        expect.objectContaining({
          id: "12345",
          organizationId: "42",
          userId: 7,
          requestId: "req-mark-expired-certs-1",
          notificationType: "CERT_EXPIRED",
          notificationAction: "EXPIRE",
          status: "DELIVERED",
          recipients: ["ops@example.com", "security@example.com"],
          recipientSummary: "ops@example.com, security@example.com",
          roles: ["ORGANIZATION_ADMIN"],
          source: "CERTIFICATE_SCHEDULER",
        }),
      ],
    });
  });

  it("should send a valid status and cap the requested page size", async () => {
    mockedApiClient.get.mockResolvedValueOnce({
      data: {
        data: [],
        page: 2,
        size: 100,
        totalElements: 0,
        totalPages: 0,
      },
    });

    await getSystemNotifications({ page: 2, size: 200, status: "FAILED" });

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.incidents.notifications,
      { params: { page: 2, size: 100, status: "FAILED" } },
    );
  });

  it("should read display metadata from the record columns, never a payload", async () => {
    mockedApiClient.get.mockResolvedValueOnce({
      data: {
        data: [
          {
            id: "newer",
            userId: null,
            organizationId: 42,
            websiteId: null,
            requestId: null,
            email: "newer@example.com",
            recipients: [],
            templateName: null,
            subject: null,
            sentBy: "EMAIL",
            integrationType: null,
            status: "DELIVERED",
            notificationType: "CERT_RENEWED",
            notificationAction: "RENEW",
            source: null,
            roles: ["ADMIN", "ADMIN"],
            failureReason: null,
            sentAt: null,
            createdAt: "2026-07-22T10:00:00Z",
            updatedAt: null,
            messageId: null,
          },
        ],
        page: 1,
        size: 20,
        totalElements: 41,
        totalPages: 3,
      },
    });

    const result = await getSystemNotifications({ page: 1, size: 20 });

    expect(result.page).toBe(1);
    expect(result.size).toBe(20);
    expect(result.totalElements).toBe(41);
    expect(result.totalPages).toBe(3);
    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toEqual(
      expect.objectContaining({
        id: "newer",
        email: "newer@example.com",
        recipientSummary: "newer@example.com",
        notificationType: "CERT_RENEWED",
        notificationAction: "RENEW",
        source: "EMAIL",
        roles: ["ADMIN"],
      }),
    );
  });

  it("should normalize invalid page filters before making the request", async () => {
    mockedApiClient.get.mockResolvedValueOnce({
      data: {
        success: true,
        message: "Notifications retrieved successfully",
        data: [],
        page: 0,
        size: 20,
        totalElements: 0,
        totalPages: 0,
      },
    });

    const result = await getSystemNotifications({ page: -1, size: 0 });

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.incidents.notifications,
      { params: { page: 0, size: 20 } },
    );
    expect(result).toEqual({
      items: [],
      page: 0,
      size: 20,
      totalElements: 0,
      totalPages: 0,
    });
  });
});
