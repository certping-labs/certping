// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React, { Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";

import OrganizationDetailPage from "@/app/(main)/settings/organizations/[slug]/page";
import { server } from "@/test/msw/server";

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: jest.fn(), push: jest.fn() }),
  usePathname: () => "/settings/organizations/acme",
  useSearchParams: () => new URLSearchParams(""),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "admin-1",
      email: "admin@acme.example",
      organizationId: "7",
      organizationName: "Acme",
      roles: ["ORGANIZATION_ADMIN"],
      permissions: ["organization:view"],
      authMethod: "LOCAL",
    },
    isLoading: false,
    isSuperAdmin: false,
  }),
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;
const ORIGINAL_APP_MODE = process.env.NEXT_PUBLIC_APP_MODE;

let ssoRequests = 0;

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  // Already-settled thenable, so `use(params)` reads it without suspending.
  const route = { slug: "acme" };
  const params = Object.assign(Promise.resolve(route), {
    status: "fulfilled",
    value: route,
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <Suspense fallback={<div>Resolving route</div>}>
        <OrganizationDetailPage params={params} />
      </Suspense>
    </QueryClientProvider>,
  );
}

describe("organization detail page", () => {
  beforeAll(() => {
    process.env.NEXT_PUBLIC_APP_MODE = "enterprise";
  });

  afterAll(() => {
    process.env.NEXT_PUBLIC_APP_MODE = ORIGINAL_APP_MODE;
  });

  beforeEach(() => {
    ssoRequests = 0;
    server.use(
      http.get(`${API_BASE_URL}/api/v1/organizations/slug/acme`, () =>
        HttpResponse.json({
          id: 7,
          name: "Acme",
          slug: "acme",
          domain: "acme.example",
          active: true,
        }),
      ),
      http.get(`${API_BASE_URL}/api/sso/*`, () => {
        ssoRequests += 1;
        return HttpResponse.json({ configs: [] });
      }),
    );
  });

  afterEach(() => {
    server.resetHandlers();
  });

  it("shows the organization and links back to Organization & Access", async () => {
    renderPage();

    expect(
      await screen.findByRole("heading", { name: "Acme" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Organization overview.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Organization" })).toHaveAttribute(
      "href",
      "/settings/organization-access?tab=organization",
    );
  });

  it("has no single sign-on controls and never calls the SSO API", async () => {
    renderPage();

    await screen.findByText("Organization overview.");
    expect(
      screen.queryByRole("link", { name: /Manage SSO/ }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/SSO sign-in/)).not.toBeInTheDocument();
    expect(ssoRequests).toBe(0);
  });
});
