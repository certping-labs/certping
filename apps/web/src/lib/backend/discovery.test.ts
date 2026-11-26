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
  deleteDiscoveryConfig,
  getDiscoveredCertificate,
  getDiscoveryConfigStatus,
  listAllDiscoveredCerts,
  listDiscoveredCerts,
  listDiscoveryConfigs,
  rerunAllDiscoveryConfigs,
  rerunDiscoveryConfig,
  triggerDiscovery,
} from "@/lib/backend/discovery";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
  delete: jest.Mock;
};

describe("discovery adapter", () => {
  beforeEach(() => {
    mockedApiClient.get.mockReset();
    mockedApiClient.post.mockReset();
    mockedApiClient.delete.mockReset();
  });

  describe("triggerDiscovery", () => {
    it("normalizes the full DiscoveryRunResponse", async () => {
      mockedApiClient.post.mockResolvedValue({
        data: {
          configId: 101,
          status: "STARTED",
          message: "Discovery has started. Results will appear shortly.",
          requestId: "req-7d01cb09",
          targetType: "AWS_ACM",
          credentialXref: "cred-aws-prod-001",
          startedAt: "2026-06-24T10:00:00Z",
          completedAt: null,
        },
      });

      const result = await triggerDiscovery("AWS_ACM", "cred-aws-prod-001");

      expect(mockedApiClient.post).toHaveBeenCalledWith(
        apiRoutes.mutation.discovery.trigger,
        { targetType: "AWS_ACM", credentialXref: "cred-aws-prod-001" },
      );
      expect(result).toEqual({
        configId: 101,
        status: "STARTED",
        message: "Discovery has started. Results will appear shortly.",
        requestId: "req-7d01cb09",
        targetType: "AWS_ACM",
        credentialXref: "cred-aws-prod-001",
        startedAt: "2026-06-24T10:00:00Z",
        completedAt: null,
      });
    });

    it("preserves a known IN_PROGRESS status (rerun while still running)", async () => {
      mockedApiClient.post.mockResolvedValue({
        data: { status: "IN_PROGRESS", targetType: "AWS_ACM" },
      });

      const result = await triggerDiscovery("AWS_ACM", "cred-1");

      expect(result.status).toBe("IN_PROGRESS");
    });
  });

  describe("getDiscoveryConfigStatus", () => {
    it("calls the config status route and normalizes a COMPLETE response", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: {
          configId: 101,
          status: "COMPLETE",
          message:
            "Discovery is complete. The certificate inventory is up to date.",
          requestId: "req-7d01cb09",
          targetType: "AWS_ACM",
          credentialXref: "cred-aws-prod-001",
          startedAt: "2026-06-24T10:00:00Z",
          completedAt: "2026-06-24T10:00:11Z",
        },
      });

      const result = await getDiscoveryConfigStatus(101);

      expect(mockedApiClient.get).toHaveBeenCalledWith(
        apiRoutes.query.discovery.triggerConfig(101),
      );
      expect(result.configId).toBe(101);
      expect(result.status).toBe("COMPLETE");
      expect(result.completedAt).toBe("2026-06-24T10:00:11Z");
    });

    it("targets the URL with the encoded configId", async () => {
      mockedApiClient.get.mockResolvedValue({ data: { status: "READY" } });

      await getDiscoveryConfigStatus(42);

      expect(mockedApiClient.get).toHaveBeenCalledWith(
        "/api/v1/discovery/trigger/42",
      );
    });
  });

  describe("listDiscoveryConfigs", () => {
    it("normalizes each saved config in the array", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: [
          {
            configId: 101,
            status: "COMPLETE",
            targetType: "AWS_ACM",
            credentialXref: "cred-aws-prod-001",
            message: "Discovery is complete.",
            requestId: "req-1",
            startedAt: "2026-06-24T10:00:00Z",
            completedAt: "2026-06-24T10:00:11Z",
          },
          {
            configId: 102,
            status: "IN_PROGRESS",
            targetType: "KUBERNETES_SECRETS",
            credentialXref: "cred-k8s",
            message: "Discovery is still running.",
            requestId: "req-2",
            startedAt: "2026-06-24T10:01:00Z",
            completedAt: null,
          },
        ],
      });

      const result = await listDiscoveryConfigs();

      expect(mockedApiClient.get).toHaveBeenCalledWith(
        apiRoutes.query.discovery.triggerConfigs,
      );
      expect(result).toHaveLength(2);
      expect(result[0].configId).toBe(101);
      expect(result[0].status).toBe("COMPLETE");
      expect(result[1].targetType).toBe("KUBERNETES_SECRETS");
      expect(result[1].status).toBe("IN_PROGRESS");
    });
  });

  describe("rerunDiscoveryConfig", () => {
    it("posts to the config route and normalizes the response", async () => {
      mockedApiClient.post.mockResolvedValue({
        data: {
          configId: 101,
          status: "STARTED",
          targetType: "AWS_ACM",
          credentialXref: "cred-1",
          message: "Discovery has started.",
        },
      });

      const result = await rerunDiscoveryConfig(101);

      expect(mockedApiClient.post).toHaveBeenCalledWith(
        apiRoutes.mutation.discovery.triggerConfig(101),
      );
      expect(result.configId).toBe(101);
      expect(result.status).toBe("STARTED");
    });
  });

  describe("rerunAllDiscoveryConfigs", () => {
    it("posts to the trigger-all route and normalizes each config", async () => {
      mockedApiClient.post.mockResolvedValue({
        data: [
          { configId: 101, status: "STARTED", targetType: "AWS_ACM" },
          {
            configId: 102,
            status: "CREDENTIAL_INVALID",
            targetType: "AZURE_KV",
          },
        ],
      });

      const result = await rerunAllDiscoveryConfigs();

      expect(mockedApiClient.post).toHaveBeenCalledWith(
        apiRoutes.mutation.discovery.triggerAll,
      );
      expect(result).toHaveLength(2);
      expect(result[1].status).toBe("CREDENTIAL_INVALID");
    });
  });

  describe("deleteDiscoveryConfig", () => {
    it("issues a DELETE to the config route", async () => {
      mockedApiClient.delete.mockResolvedValue({ status: 204 });

      await deleteDiscoveryConfig(101);

      expect(mockedApiClient.delete).toHaveBeenCalledWith(
        apiRoutes.mutation.discovery.triggerConfig(101),
      );
    });
  });

  describe("listDiscoveredCerts", () => {
    it("requests the first backend page with the discovery batch size by default", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: {
          content: [],
          totalElements: 0,
          totalPages: 1,
          number: 0,
          size: 100,
        },
      });

      await listDiscoveredCerts();

      expect(mockedApiClient.get).toHaveBeenCalledWith(
        apiRoutes.query.discovery.certs,
        { params: { page: 0, size: 100 } },
      );
    });

    it("includes server-side discovery filters in the list request", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: {
          content: [],
          totalElements: 0,
          totalPages: 1,
          number: 0,
          size: 100,
        },
      });

      await listDiscoveredCerts({
        domain: "api.example.com",
        managed: false,
        targetType: "AWS_ACM",
        expiresWithinDays: 30,
      });

      expect(mockedApiClient.get).toHaveBeenCalledWith(
        apiRoutes.query.discovery.certs,
        {
          params: {
            domain: "api.example.com",
            managed: false,
            targetType: "AWS_ACM",
            expiresWithinDays: 30,
            page: 0,
            size: 100,
          },
        },
      );
    });

    it("paginates discovered certificates across all backend pages", async () => {
      mockedApiClient.get
        .mockResolvedValueOnce({
          data: {
            content: [{ id: 1, domain: "one.example.com" }],
            totalElements: 2,
            totalPages: 2,
            number: 0,
            size: 1,
          },
        })
        .mockResolvedValueOnce({
          data: {
            content: [{ id: 2, domain: "two.example.com" }],
            totalElements: 2,
            totalPages: 2,
            number: 1,
            size: 1,
          },
        });

      const result = await listAllDiscoveredCerts({ size: 1 });

      expect(mockedApiClient.get).toHaveBeenNthCalledWith(
        1,
        apiRoutes.query.discovery.certs,
        { params: { page: 0, size: 1 } },
      );
      expect(mockedApiClient.get).toHaveBeenNthCalledWith(
        2,
        apiRoutes.query.discovery.certs,
        { params: { page: 1, size: 1 } },
      );
      expect(result.map((cert) => cert.domain)).toEqual([
        "one.example.com",
        "two.example.com",
      ]);
    });
  });

  describe("getDiscoveredCertificate", () => {
    it("targets the encoded cert route and keeps providerData null for non-K8s", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: {
          id: 301,
          organizationId: 42,
          targetType: "AWS_ACM",
          resourceId: "arn:aws:acm:us-east-1:123:certificate/abc",
          domain: "api.example.com",
          certStatus: "ISSUED",
          inUseBy: ["api.example.com"],
          sanDomains: ["api.example.com", "www.example.com"],
          inventoryStatus: "PRESENT",
          missingSince: null,
          managed: false,
          discoveredAt: "2026-06-24T10:00:07Z",
          providerData: null,
        },
      });

      const result = await getDiscoveredCertificate(301);

      expect(mockedApiClient.get).toHaveBeenCalledWith(
        "/api/v1/discovery/certs/301",
      );
      expect(result.inventoryStatus).toBe("PRESENT");
      expect(result.sanDomains).toEqual(["api.example.com", "www.example.com"]);
      expect(result.providerData).toBeNull();
    });

    it("normalizes the Kubernetes providerData (source, usages, impact)", async () => {
      mockedApiClient.get.mockResolvedValue({
        data: {
          id: 303,
          organizationId: 42,
          targetType: "KUBERNETES_SECRETS",
          resourceId: "k8s://prod-aks/frontend/secrets/api-tls",
          domain: "api.example.com",
          certStatus: "ISSUED",
          inUseBy: ["frontend/Ingress/api-ingress"],
          sanDomains: ["api.example.com"],
          inventoryStatus: "PRESENT",
          managed: false,
          discoveredAt: "2026-06-24T10:10:09Z",
          providerData: {
            clusterName: "prod-aks",
            usageComplete: true,
            impactComplete: true,
            unreadableResourceTypes: [],
            source: {
              apiVersion: "v1",
              kind: "Secret",
              namespace: "frontend",
              name: "api-tls",
              fingerprintSha256: "A1:B2:C3:D4",
            },
            usages: [
              {
                kind: "Ingress",
                namespace: "frontend",
                name: "api-ingress",
                usageType: "TLS_TERMINATION",
                hostnames: ["api.example.com"],
                backendServices: [
                  {
                    namespace: "frontend",
                    name: "api-service",
                    portName: "https",
                    portNumber: null,
                  },
                ],
                affectedWorkloads: [
                  {
                    kind: "Deployment",
                    namespace: "frontend",
                    name: "api",
                    containers: ["api"],
                  },
                ],
                confidence: "HIGH",
              },
            ],
            impact: {
              externallyServed: true,
              directlyMountedByWorkloads: false,
              affectedHostnames: ["api.example.com"],
              affectedServices: ["frontend/api-service"],
              affectedWorkloads: ["frontend/Deployment/api"],
              summary: "Expiry can break external TLS for api.example.com.",
            },
            warnings: [],
          },
        },
      });

      const result = await getDiscoveredCertificate(303);

      expect(result.providerData?.clusterName).toBe("prod-aks");
      expect(result.providerData?.source?.name).toBe("api-tls");
      expect(result.providerData?.usages).toHaveLength(1);
      expect(result.providerData?.usages[0].backendServices[0].name).toBe(
        "api-service",
      );
      expect(
        result.providerData?.usages[0].affectedWorkloads[0].containers,
      ).toEqual(["api"]);
      expect(result.providerData?.impact?.externallyServed).toBe(true);
    });
  });
});
