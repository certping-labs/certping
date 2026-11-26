// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";

import CertManagerPage from "@/app/(main)/cert-manager/page";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { server } from "@/test/msw/server";

// Gating is the subject here, so the real flag hooks read the real store.
jest.unmock("@/hooks/use-feature-flags");

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: jest.fn(), push: jest.fn() }),
  usePathname: () => "/cert-manager",
  useSearchParams: () => new URLSearchParams("renewal=expiring_30_days"),
}));

jest.mock("@/hooks/use-mobile", () => ({ useIsMobile: () => false }));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "user-1",
      email: "user@example.com",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: ["certificate:read", "deployments:view"],
      authMethod: "LOCAL",
    },
    isLoading: false,
    isSuperAdmin: false,
  }),
}));

jest.mock("@/components/cert-manager/certificate-management-dialog", () => ({
  CertificateManagementDialog: () => null,
}));
jest.mock("@/components/cert-manager/manual-txt-records-dialog", () => ({
  ManualTxtRecordsDialog: () => null,
}));

// The table's own rendering is covered elsewhere; this suite only needs to
// see which filters and default filter values the page hands it.
jest.mock("@/components/ui/custom-table", () => ({
  CustomTable: ({
    filters,
    defaultFilterValues,
  }: {
    filters?: { id: string; label?: string }[];
    defaultFilterValues?: Record<string, string>;
  }) => (
    <div>
      <ul aria-label="Table filters">
        {(filters ?? []).map((filter) => (
          <li key={filter.id}>{filter.label}</li>
        ))}
      </ul>
      <output aria-label="Default filters">
        {JSON.stringify(defaultFilterValues ?? {})}
      </output>
    </div>
  ),
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

function setFlags(effectiveMap: Record<string, boolean>) {
  useFeatureFlagStore.getState().setEffectiveMap(effectiveMap);
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <CertManagerPage />
    </QueryClientProvider>,
  );
}

describe("certificate list feature gates", () => {
  beforeEach(() => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-1",
              domain: "prod.example.com",
              status: "ACTIVE",
              caProvider: "DIGICERT",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        }),
      ),
    );
  });

  afterEach(() => {
    server.resetHandlers();
    useFeatureFlagStore.getState().reset();
  });

  it("offers deployments and the expiry filter while both features are on", async () => {
    setFlags({ CERTIFICATE_DEPLOYMENT: true, CERTIFICATE_RENEWAL: true });

    renderPage();

    expect(
      await screen.findByRole("link", { name: "View deployments" }),
    ).toHaveAttribute("href", "/cert-manager/deployments");
    expect(screen.getByText("Expiry")).toBeInTheDocument();
    expect(screen.getByLabelText("Default filters")).toHaveTextContent(
      '"renewalWindow":"expiring_30_days"',
    );
  });

  it("hides deployments but keeps the expiry filter and its link while they are off", async () => {
    setFlags({ CERTIFICATE_DEPLOYMENT: false, CERTIFICATE_RENEWAL: false });

    renderPage();

    expect(await screen.findByText("Management")).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "View deployments" }),
    ).not.toBeInTheDocument();
    // Expiry is a fact about the certificate, not a renewal feature.
    expect(screen.getByText("Expiry")).toBeInTheDocument();
    expect(screen.getByLabelText("Default filters")).toHaveTextContent(
      '"renewalWindow":"expiring_30_days"',
    );
  });

  it("treats a flag missing from the map as off", async () => {
    setFlags({});

    renderPage();

    expect(await screen.findByText("Management")).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "View deployments" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Expiry")).toBeInTheDocument();
  });
});
