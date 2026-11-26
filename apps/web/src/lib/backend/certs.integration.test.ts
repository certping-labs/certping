// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { http, HttpResponse } from "msw";

import {
  getCertificateDetail,
  issueCertificate,
  listCertificatesPage,
} from "@/lib/backend/certs";
import { server } from "@/test/msw/server";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

describe("certs adapter integration (MSW)", () => {
  beforeAll(() => {
    server.listen({ onUnhandledFrame: "error" });
  });

  afterEach(() => {
    server.resetHandlers();
  });

  afterAll(() => {
    server.close();
  });

  it("loads the typed certificate list via real apiClient + MSW", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-msw-1",
              domain: "msw.example.com",
              status: "ACTIVE",
              deploymentCredentialXrefs: ["dep-1"],
              dnsConfigXref: { "msw.example.com": "dns-1" },
            },
          ],
          page: 0,
          size: 20,
          totalItems: 1,
          totalPages: 1,
        }),
      ),
    );

    const result = await listCertificatesPage();

    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toEqual(
      expect.objectContaining({
        certificateXref: "cert-msw-1",
        domain: "msw.example.com",
        status: "ACTIVE",
        dnsConfigXref: "dns-1",
        deploymentCredentialXrefs: ["dep-1"],
      }),
    );
  });

  it("falls back from detail 404 to list lookup and returns recovered detail", async () => {
    let detailCallCount = 0;

    server.use(
      http.get(
        `${API_BASE_URL}/api/v1/certs/:certificateXref`,
        ({ params }) => {
          detailCallCount += 1;
          if (
            detailCallCount === 1 &&
            params.certificateXref === "legacy.example.com"
          ) {
            return HttpResponse.json({ message: "Not Found" }, { status: 404 });
          }
          return HttpResponse.json({
            certificateXref: "cert-msw-recovered",
            domain: "legacy.example.com",
            status: "ACTIVE",
          });
        },
      ),
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-msw-recovered",
              domain: "legacy.example.com",
              status: "PENDING",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        }),
      ),
    );

    const result = await getCertificateDetail("legacy.example.com");
    expect(result.certificateXref).toBe("cert-msw-recovered");
    expect(result.domain).toBe("legacy.example.com");
    expect(detailCallCount).toBe(2);
  });

  it("posts issuance request through real api client and returns the typed response", async () => {
    server.use(
      http.post(`${API_BASE_URL}/api/v1/certs/issue`, async ({ request }) => {
        const body = (await request.json()) as Record<string, unknown>;
        expect(body.domain).toBe("issue.example.com");
        return HttpResponse.json({
          certificateXref: "cert-msw-issued",
          domain: "issue.example.com",
          status: "PENDING",
        });
      }),
    );

    const result = await issueCertificate({
      domain: "issue.example.com",
      wildcard: false,
      san: false,
      caProvider: "DIGICERT",
      dnsCredentialXref: "dns-msw-1",
      sanDomainEntries: [],
      deploymentTargets: [],
    });

    expect(result).toEqual(
      expect.objectContaining({
        certificateXref: "cert-msw-issued",
        domain: "issue.example.com",
        status: "PENDING",
      }),
    );
  });
});
