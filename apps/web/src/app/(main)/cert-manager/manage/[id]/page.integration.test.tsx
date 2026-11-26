// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";

import ManageCertificatePage from "@/app/(main)/cert-manager/manage/[id]/page";
import { server } from "@/test/msw/server";

const mockUseAuth = jest.fn();
const mockRedirect = jest.fn((href: string) => {
  void href;
  return null;
});

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockUseAuth(),
}));

jest.mock("next/navigation", () => ({
  redirect: (href: string) => mockRedirect(href),
}));

jest.mock("@/components/cert-manager/certificate/cert-page", () => ({
  CertificateDetails: ({
    certificate,
  }: {
    certificate: { domain: string };
  }) => <div data-testid="certificate-details">{certificate.domain}</div>,
}));
jest.mock("@/components/common/unautorised", () => ({
  Unauthorised: () => <div>Access Restricted</div>,
}));
jest.mock("@/components/common/error", () => ({
  SomethingWentWrong: ({
    title,
    description,
  }: {
    title: string;
    description?: string;
  }) => (
    <div>
      <div>{title}</div>
      <div>{description}</div>
    </div>
  ),
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

const CERTIFICATE_DETAILS_RESPONSE = {
  certificateXref: "cert-1",
  domain: "prod.example.com",
  status: "ACTIVE",
  caProvider: "DIGICERT",
  validFrom: "2026-01-01T00:00:00Z",
  validTo: "2027-01-01T00:00:00Z",
  san: false,
  wildcard: false,
  sanDomains: [],
};

async function renderPage(certificateId = "cert-1") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  await act(async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <React.Suspense fallback={<div>Loading route...</div>}>
          <ManageCertificatePage
            params={Promise.resolve({ id: certificateId })}
          />
        </React.Suspense>
      </QueryClientProvider>,
    );
  });
}

describe("manage certificate page integration (UI + MSW)", () => {
  beforeEach(() => {
    mockRedirect.mockReset();
    mockUseAuth.mockReturnValue({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
      },
      isLoading: false,
      isSuperAdmin: false,
    });
  });

  afterEach(() => {
    server.resetHandlers();
    mockUseAuth.mockReset();
  });

  it("shows unauthorized state when user cannot view certificates", async () => {
    mockUseAuth.mockReturnValue({
      user: {
        id: "user-2",
        email: "unauthorized@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["credential:read"],
        authMethod: "LOCAL",
      },
      isLoading: false,
      isSuperAdmin: false,
    });

    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs/:certificateXref`, () =>
        HttpResponse.json(CERTIFICATE_DETAILS_RESPONSE),
      ),
    );

    await renderPage();

    expect(await screen.findByText("Access Restricted")).toBeInTheDocument();
    expect(screen.queryByTestId("certificate-details")).not.toBeInTheDocument();
  });

  it("shows error state when certificate details fetch fails", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs/:certificateXref`, () =>
        HttpResponse.json({ message: "backend unavailable" }, { status: 500 }),
      ),
    );

    await renderPage();

    expect(
      await screen.findByText("Failed to load certificate details"),
    ).toBeInTheDocument();
    expect(screen.getByText("backend unavailable")).toBeInTheDocument();
  });

  it("renders certificate details when fetch succeeds", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs/:certificateXref`, () =>
        HttpResponse.json(CERTIFICATE_DETAILS_RESPONSE),
      ),
    );

    await renderPage();

    expect(await screen.findByTestId("certificate-details")).toHaveTextContent(
      "prod.example.com",
    );
  });

  it("replaces a renewal-success route with the current lifecycle certificate", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs/history`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-renew-success",
              domain: "prod.example.com",
              status: "RENEW_SUCCESS",
              userDomainCertId: "101",
            },
            {
              certificateXref: "cert-active-current",
              domain: "prod.example.com",
              status: "ACTIVE",
              userDomainCertId: "101",
            },
          ],
          page: 0,
          size: 50,
          totalItems: 2,
          totalPages: 1,
        }),
      ),
      http.get(`${API_BASE_URL}/api/v1/certs/:certificateXref`, () =>
        HttpResponse.json({
          ...CERTIFICATE_DETAILS_RESPONSE,
          certificateXref: "cert-renew-success",
          status: "RENEW_SUCCESS",
          userDomainCertId: "101",
        }),
      ),
    );

    await renderPage("cert-renew-success");

    await waitFor(() =>
      expect(mockRedirect).toHaveBeenCalledWith(
        "/cert-manager/manage/cert-active-current",
      ),
    );
    expect(screen.queryByTestId("certificate-details")).not.toBeInTheDocument();
  });
});
