// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { http, HttpResponse } from "msw";

import {
  createDeploymentCredentialReference,
  createDnsCredentialReference,
  listCredentialReferences,
  updateCredentialReference,
} from "@/lib/backend/credentials";
import { server } from "@/test/msw/server";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

describe("credentials adapter integration (MSW)", () => {
  beforeAll(() => {
    server.listen({ onUnhandledFrame: "error" });
  });

  afterEach(() => {
    server.resetHandlers();
  });

  afterAll(() => {
    server.close();
  });

  it("lists DNS credential references and normalizes provider metadata", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, ({ request }) => {
        const requestUrl = new URL(request.url);
        expect(requestUrl.searchParams.get("type")).toBe("DNS");

        return HttpResponse.json({
          items: [
            {
              credentialXref: "cred-dns-1",
              provider: "CLOUDFLARE",
              type: "DNS",
              description: "Cloudflare DNS",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/cloudflare",
            },
          ],
          totalItems: 1,
        });
      }),
    );

    const result = await listCredentialReferences("DNS");
    expect(result.items).toEqual([
      expect.objectContaining({
        credentialXref: "cred-dns-1",
        provider: "CLOUDFLARE",
        providerKey: "cloudflare",
        type: "DNS",
      }),
    ]);
  });

  it("creates and updates deployment credential references for new providers", async () => {
    server.use(
      http.post(
        `${API_BASE_URL}/api/v1/credentials/deployment`,
        async ({ request }) => {
          const payload = (await request.json()) as Record<string, unknown>;
          expect(payload.provider).toBe("AKAMAI_CPS");

          return HttpResponse.json({
            credentialXref: "cred-deploy-1",
            provider: "AKAMAI_CPS",
            type: "DEPLOYMENT",
            description: "Akamai deployment",
            status: "ACTIVE",
            secretHandle: "https://vault/secrets/akamai",
          });
        },
      ),
      http.put(
        `${API_BASE_URL}/api/v1/credentials/:credentialXref`,
        async ({ params, request }) => {
          const payload = (await request.json()) as Record<string, unknown>;
          expect(params.credentialXref).toBe("cred-deploy-1");
          expect(payload.configJson).toBe('{"authProvider":"SA_INCLUSTER"}');

          return HttpResponse.json({
            credentialXref: "cred-deploy-1",
            provider: "F5_BIGIP",
            type: "DEPLOYMENT",
            status: "ACTIVE",
            updatedAt: "2026-07-22T10:00:00Z",
            message: "Credential scope updated.",
          });
        },
      ),
    );

    const created = await createDeploymentCredentialReference({
      provider: "AKAMAI_CPS",
      description: "Akamai deployment",
      secretHandle: "https://vault/secrets/akamai",
    });
    expect(created).toEqual(
      expect.objectContaining({
        credentialXref: "cred-deploy-1",
        providerKey: "akamai",
      }),
    );

    const updated = await updateCredentialReference("cred-deploy-1", {
      secretHandle: "https://vault/secrets/f5",
      configJson: '{"authProvider":"SA_INCLUSTER"}',
    });
    expect(updated).toEqual(
      expect.objectContaining({
        provider: "F5_BIGIP",
        type: "DEPLOYMENT",
        message: "Credential scope updated.",
      }),
    );
  });

  it("creates DNS credential reference through the DNS endpoint", async () => {
    server.use(
      http.post(
        `${API_BASE_URL}/api/v1/credentials/dns`,
        async ({ request }) => {
          const payload = (await request.json()) as Record<string, unknown>;
          expect(payload.provider).toBe("NAMEDOTCOM");
          return HttpResponse.json({
            credentialXref: "cred-dns-2",
            provider: "NAMEDOTCOM",
            type: "DNS",
            description: "Name.com DNS",
            status: "ACTIVE",
          });
        },
      ),
    );

    const created = await createDnsCredentialReference({
      provider: "NAMEDOTCOM",
      description: "Name.com DNS",
      secretHandle: "https://vault/secrets/namecom",
    });

    expect(created).toEqual(
      expect.objectContaining({
        credentialXref: "cred-dns-2",
        providerKey: "namecom",
      }),
    );
  });
});
