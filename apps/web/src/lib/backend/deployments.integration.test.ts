// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { http, HttpResponse } from "msw";

import {
  createDeployment,
  queryDeployments,
  queryUserDomainCertificateDeploymentSummaries,
} from "@/lib/backend/deployments";
import { server } from "@/test/msw/server";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

describe("deployments adapter integration (MSW)", () => {
  beforeAll(() => {
    server.listen({ onUnhandledFrame: "error" });
  });

  afterEach(() => {
    server.resetHandlers();
  });

  afterAll(() => {
    server.close();
  });

  it("queries deployments and normalizes response shape", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/deployments`, () =>
        HttpResponse.json({
          items: [
            {
              id: "dep-msw-1",
              requestId: "req-msw-1",
              status: "SUCCESS",
              domain: "integration.example.com",
            },
          ],
          page: 0,
          size: 20,
          totalPages: 1,
          totalItems: 1,
          mode: "list",
        }),
      ),
    );

    const result = await queryDeployments({ status: "SUCCESS" });
    expect(result.items).toEqual([
      expect.objectContaining({
        id: "dep-msw-1",
        requestId: "req-msw-1",
        status: "SUCCESS",
      }),
    ]);
  });

  it("creates deployment and reads user-domain summary via live adapter path", async () => {
    server.use(
      http.post(
        `${API_BASE_URL}/api/v1/certs/:certificateXref/deploy`,
        async ({ request }) => {
          const body = (await request.json()) as Record<string, unknown>;
          expect(body.deploymentCredentialXref).toBe("cred-msw-1");
          expect(body.targetType).toBe("AZURE_KV");
          return HttpResponse.json({
            certificateXref: "cert-msw-1",
            domain: "integration.example.com",
            status: "DEPLOYING",
          });
        },
      ),
      http.get(
        `${API_BASE_URL}/api/v1/deployments/user-domain-certs/summary`,
        () =>
          HttpResponse.json({
            items: [
              {
                userDomainCertId: 7,
                domain: "integration.example.com",
                deploymentsRequested: 1,
                deploymentsSucceeded: 0,
                deploymentsFailed: 0,
              },
            ],
            page: 0,
            size: 20,
            totalItems: 1,
            totalPages: 1,
          }),
      ),
    );

    const deployment = await createDeployment({
      certificateXref: "cert-msw-1",
      deploymentCredentialXref: "cred-msw-1",
      targetType: "AZURE_KV",
    });
    expect(deployment).toEqual(
      expect.objectContaining({
        certificateXref: "cert-msw-1",
        status: "DEPLOYING",
      }),
    );

    const summaries = await queryUserDomainCertificateDeploymentSummaries({
      userDomainCertificateId: "7",
    });
    expect(summaries.items).toEqual([
      expect.objectContaining({
        userDomainCertId: 7,
        domain: "integration.example.com",
      }),
    ]);
  });
});
