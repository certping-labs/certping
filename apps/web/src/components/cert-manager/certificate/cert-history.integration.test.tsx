// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";

import { CertHistory } from "@/components/cert-manager/certificate/cert-history";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { server } from "@/test/msw/server";
import type { SsoUser } from "@/types/auth";
import type { SSLCertificateDetails } from "@/types/ssl";

// The Deployments button is flag-gated; drive the real flag store.
jest.unmock("@/hooks/use-feature-flags");

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

const viewer = {
  id: "u1",
  email: "viewer@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions: ["certificate:read", "deployments:view"],
  authMethod: "LOCAL",
} as SsoUser;

const certificate = {
  certificateXref: "cert-current",
  userDomainCertId: "42",
  domain: "prod.example.com",
  status: "ACTIVE",
} as SSLCertificateDetails;

function renderHistory() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <CertHistory certificate={certificate} />
    </QueryClientProvider>,
  );
}

describe("CertHistory deployment links", () => {
  beforeEach(() => {
    useAuthStore.setState({ user: viewer });
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs/history`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-current",
              userDomainCertId: 42,
              domain: "prod.example.com",
              status: "ACTIVE",
              issuer: "R3",
            },
          ],
          page: 0,
          size: 20,
          totalItems: 1,
          totalPages: 1,
        }),
      ),
    );
  });

  afterEach(() => {
    server.resetHandlers();
    useFeatureFlagStore.getState().reset();
    useAuthStore.setState({ user: null });
  });

  it("links each record to its deployments while deployment is on", async () => {
    useFeatureFlagStore
      .getState()
      .setEffectiveMap({ CERTIFICATE_DEPLOYMENT: true });

    renderHistory();

    const link = await screen.findByRole("link", { name: "Deployments" });
    expect(link.getAttribute("href")).toMatch(
      /^\/cert-manager\/deployments\/42\?/,
    );
  });

  it("offers no deployments link while deployment is off", async () => {
    useFeatureFlagStore
      .getState()
      .setEffectiveMap({ CERTIFICATE_DEPLOYMENT: false });

    renderHistory();

    expect(await screen.findByText("prod.example.com")).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Deployments" }),
    ).not.toBeInTheDocument();
  });
});

describe("CertHistory renewal trigger", () => {
  afterEach(() => {
    server.resetHandlers();
    useAuthStore.setState({ user: null });
  });

  it("says which records a scheduled or a manual renewal produced", async () => {
    useAuthStore.setState({ user: viewer });
    const record = (
      certificateXref: string,
      renewalTrigger: "SCHEDULED" | "MANUAL" | null,
    ) => ({
      certificateXref,
      userDomainCertId: 42,
      domain: "prod.example.com",
      status: "ACTIVE",
      issuer: "R3",
      renewalTrigger,
    });
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs/history`, () =>
        HttpResponse.json({
          items: [
            record("cert-current", "SCHEDULED"),
            record("cert-middle", "MANUAL"),
            record("cert-first", null),
          ],
          page: 0,
          size: 20,
          totalItems: 3,
          totalPages: 1,
        }),
      ),
    );

    renderHistory();

    expect(
      (await screen.findAllByText("Scheduled renewal")).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText("Manual renewal").length).toBeGreaterThan(0);
  });
});
