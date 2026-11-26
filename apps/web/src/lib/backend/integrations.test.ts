// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    supportApiClient: {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    },
  };
});

import { apiRoutes, supportApiClient } from "@/lib/api";
import {
  createIntegration,
  createPagerDutyIncident,
  createServiceNowIncident,
  deleteIntegration,
  getIntegration,
  listIncidentHistory,
  listIntegrations,
  updateIntegration,
} from "@/lib/backend/integrations";

const mockedSupportApiClient = supportApiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
  put: jest.Mock;
  delete: jest.Mock;
};

describe("integrations adapter", () => {
  beforeEach(() => {
    mockedSupportApiClient.get.mockReset();
    mockedSupportApiClient.post.mockReset();
    mockedSupportApiClient.put.mockReset();
    mockedSupportApiClient.delete.mockReset();
  });

  it("returns typed integration lists", async () => {
    mockedSupportApiClient.get
      .mockResolvedValueOnce({
        data: [
          {
            id: 1,
            provider: "SLACK",
            status: "ACTIVE",
            createdAt: "2026-05-01T10:00:00Z",
          },
        ],
      })
      .mockResolvedValueOnce({
        data: [
          {
            id: 3,
            provider: "PAGERDUTY",
            status: "DISABLED",
            updatedAt: "2026-05-02T10:00:00Z",
          },
        ],
      });

    const fromArray = await listIntegrations();
    const fromWrapped = await listIntegrations();

    expect(fromArray).toEqual([
      expect.objectContaining({
        id: 1,
        provider: "SLACK",
        status: "ACTIVE",
        createdAt: "2026-05-01T10:00:00Z",
      }),
    ]);
    expect(fromWrapped).toEqual([
      expect.objectContaining({
        id: 3,
        provider: "PAGERDUTY",
        status: "DISABLED",
        updatedAt: "2026-05-02T10:00:00Z",
      }),
    ]);
  });

  it("returns a typed integration detail", async () => {
    const integration = { id: 20, provider: "SLACK", status: "ACTIVE" };
    mockedSupportApiClient.get.mockResolvedValueOnce({
      data: integration,
    });

    await expect(getIntegration(20)).resolves.toBe(integration);
    expect(mockedSupportApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.integrations.detail(20),
    );
  });

  it("strips empty fields for create and update payloads", async () => {
    mockedSupportApiClient.post.mockResolvedValueOnce({
      data: { id: 9, provider: "TEAMS", status: "DISABLED" },
    });
    mockedSupportApiClient.put.mockResolvedValueOnce({
      data: { id: 9, provider: "TEAMS", status: "ACTIVE" },
    });

    const created = await createIntegration({
      provider: "SERVICENOW_ITSM",
      instanceUrl: "https://servicenow.example",
      clientId: "client-1",
      clientSecret: "secret-1",
      oauthScope: "   ",
    });
    const updated = await updateIntegration(9, {
      instanceUrl: "https://servicenow.example/v2",
      clientId: "client-2",
      clientSecret: "secret-2",
      oauthScope: "",
    });

    expect(mockedSupportApiClient.post).toHaveBeenCalledWith(
      apiRoutes.mutation.integrations.create,
      {
        provider: "SERVICENOW_ITSM",
        instanceUrl: "https://servicenow.example",
        clientId: "client-1",
        clientSecret: "secret-1",
      },
    );
    expect(mockedSupportApiClient.put).toHaveBeenCalledWith(
      apiRoutes.mutation.integrations.update(9),
      {
        instanceUrl: "https://servicenow.example/v2",
        clientId: "client-2",
        clientSecret: "secret-2",
      },
    );
    expect(created).toEqual(
      expect.objectContaining({
        id: 9,
        provider: "TEAMS",
        status: "DISABLED",
      }),
    );
    expect(updated).toEqual(
      expect.objectContaining({ id: 9, provider: "TEAMS", status: "ACTIVE" }),
    );
  });

  it("deletes integrations and returns typed incident history pages", async () => {
    mockedSupportApiClient.delete.mockResolvedValueOnce({});
    mockedSupportApiClient.get.mockResolvedValueOnce({
      data: {
        items: [
          {
            id: 17,
            provider: "SERVICENOW_ITSM",
            source: "MANUAL",
            actorUserId: 200,
            summary: "Investigate cert alert",
            externalIncidentId: "INC-001",
            createdAt: "2026-05-02T08:00:00Z",
          },
        ],
        page: 0,
        size: 50,
        totalElements: 1,
        totalPages: 1,
      },
    });

    await deleteIntegration(17);
    const history = await listIncidentHistory();

    expect(mockedSupportApiClient.delete).toHaveBeenCalledWith(
      apiRoutes.mutation.integrations.delete(17),
    );
    expect(mockedSupportApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.supportIncidents.list,
      { params: { page: 0, size: 50 } },
    );
    expect(history).toEqual({
      page: 0,
      size: 50,
      totalElements: 1,
      totalPages: 1,
      items: [
        expect.objectContaining({
          id: 17,
          provider: "SERVICENOW_ITSM",
          source: "MANUAL",
          createdAt: "2026-05-02T08:00:00Z",
        }),
      ],
    });
  });

  it("passes through incident creation responses", async () => {
    mockedSupportApiClient.post
      .mockResolvedValueOnce({
        data: {
          status: "created",
          message: "Incident created",
          dedupKey: "dedup-1",
        },
      })
      .mockResolvedValueOnce({
        data: {
          sysId: "SNOW-1",
          number: "INC001",
          recordUrl: "https://servicenow.example/incident/INC001",
        },
      });

    const pagerDutyResponse = await createPagerDutyIncident({
      alertId: 10,
      title: "PagerDuty title",
      severity: "CRITICAL",
      source: "certping",
      dedupKey: "",
      component: "scheduler",
      className: "cert-expiry",
      links: [],
      customDetails: {},
    });
    const serviceNowResponse = await createServiceNowIncident({
      alertId: 11,
      shortDescription: "ServiceNow short description",
      description: "Long description",
      urgency: "HIGH",
      impact: "MEDIUM",
    });

    expect(mockedSupportApiClient.post).toHaveBeenNthCalledWith(
      1,
      apiRoutes.mutation.supportIncidents.createPagerDuty,
      {
        alertId: 10,
        title: "PagerDuty title",
        severity: "CRITICAL",
        source: "certping",
        component: "scheduler",
        className: "cert-expiry",
        links: [],
        customDetails: {},
      },
    );
    expect(mockedSupportApiClient.post).toHaveBeenNthCalledWith(
      2,
      apiRoutes.mutation.supportIncidents.createServiceNow,
      {
        alertId: 11,
        shortDescription: "ServiceNow short description",
        description: "Long description",
        urgency: "HIGH",
        impact: "MEDIUM",
      },
    );
    expect(pagerDutyResponse.status).toBe("created");
    expect(serviceNowResponse.sysId).toBe("SNOW-1");
  });
});
