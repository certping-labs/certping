// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import UserDomainCertificateDeploymentsPage from "@/app/(main)/cert-manager/deployments/[userDomainCertificateId]/page";
import { useAuthStore } from "@/stores/auth-store";
import { seedFeatureFlags } from "@/test/feature-flags";
import { server } from "@/test/msw/server";

const replaceMock = jest.fn();
const pushMock = jest.fn();
let searchParamsValue = "domain=alpha.example.com";

let currentPermissions = ["deployments:view", "certificate:deploy"];

jest.mock("next/navigation", () => ({
  useParams: () => ({ userDomainCertificateId: "101" }),
  useRouter: () => ({
    replace: replaceMock,
    push: pushMock,
  }),
  usePathname: () => "/cert-manager/deployments/101",
  useSearchParams: () => new URLSearchParams(searchParamsValue),
}));

jest.mock("@/components/cert-manager/deploy-new-cert-dialog", () => ({
  DeployNewCertDialog: () => null,
}));

jest.mock("@/components/common/metric-card", () => ({
  MetricStrip: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MetricCard: ({ title, value }: { title: string; value: number }) => (
    <div>
      {title}:{value}
    </div>
  ),
}));

jest.mock("@/components/common/unautorised", () => ({
  Unauthorised: () => <div>Access Restricted</div>,
}));

jest.mock("@/components/ui/custom-table", () => ({
  CustomTable: ({
    data,
    onSearchTermChange,
    emptyTableMsg,
  }: {
    data: Array<{ id: string | number; domain?: string; requestId?: string }>;
    onSearchTermChange?: (value: string) => void;
    emptyTableMsg?: string;
  }) => {
    const [term, setTerm] = React.useState("");
    const visible = data.filter((row) => {
      const query = term.toLowerCase();
      return (
        (row.domain || "").toLowerCase().includes(query) ||
        (row.requestId || "").toLowerCase().includes(query)
      );
    });

    return (
      <div>
        <input
          placeholder="Search domains, certificate refs, request IDs, status, targets, or credentials"
          value={term}
          onChange={(event) => {
            setTerm(event.target.value);
            onSearchTermChange?.(event.target.value);
          }}
        />
        {visible.length === 0 ? <div>{emptyTableMsg}</div> : null}
        {visible.map((row) => (
          <div data-testid="deployment-row" key={String(row.id)}>
            {row.domain || row.requestId}
          </div>
        ))}
      </div>
    );
  },
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "user-1",
      email: "user@example.com",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: currentPermissions,
      authMethod: "LOCAL",
    },
    isSuperAdmin: false,
    isLoading: false,
  }),
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  render(
    <QueryClientProvider client={queryClient}>
      <UserDomainCertificateDeploymentsPage />
    </QueryClientProvider>,
  );
}

describe("deployment detail page integration (UI + MSW)", () => {
  beforeEach(() => {
    // FeatureRouteGate only mounts this page once deployment is confirmed on.
    seedFeatureFlags({ CERTIFICATE_DEPLOYMENT: true });
    currentPermissions = ["deployments:view", "certificate:deploy"];
    searchParamsValue = "domain=alpha.example.com";
    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: currentPermissions,
        authMethod: "LOCAL",
      },
      isSuperAdmin: false,
      isLoading: false,
      expiresAt: Date.now() + 60_000,
    });
  });

  afterEach(() => {
    server.resetHandlers();
    replaceMock.mockReset();
    pushMock.mockReset();
  });

  it("shows unauthorized state when user lacks permission", async () => {
    currentPermissions = [];
    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: currentPermissions,
        authMethod: "LOCAL",
      },
      isSuperAdmin: false,
      isLoading: false,
      expiresAt: Date.now() + 60_000,
    });

    renderPage();

    expect(await screen.findByText("Access Restricted")).toBeInTheDocument();
  });

  it("shows empty state when deployments list is empty", async () => {
    currentPermissions = ["deployments:view", "certificate:deploy"];

    server.use(
      http.get(`${API_BASE_URL}/api/v1/deployments`, () =>
        HttpResponse.json({
          items: [],
          page: 0,
          size: 0,
          totalItems: 0,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(
      await screen.findByText("No deployments found for the current filters."),
    ).toBeInTheDocument();
    expect(screen.getByText("deployments:0")).toBeInTheDocument();
  });

  it("renders deployment rows and filters by search", async () => {
    currentPermissions = ["deployments:view", "certificate:deploy"];
    const user = userEvent.setup();

    server.use(
      http.get(`${API_BASE_URL}/api/v1/deployments`, () =>
        HttpResponse.json({
          items: [
            {
              id: 1,
              requestId: "req-1",
              userDomainCertId: 101,
              domain: "alpha.example.com",
              status: "SUCCESS",
              targetType: "AKAMAI",
              flowType: "MANUAL",
            },
            {
              id: 2,
              requestId: "req-2",
              userDomainCertId: 101,
              domain: "beta.example.com",
              status: "FAILED_DEPLOYMENT",
              targetType: "CLOUDFLARE",
              flowType: "MANUAL",
            },
          ],
          page: 0,
          size: 2,
          totalItems: 2,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(await screen.findAllByText("alpha.example.com")).toHaveLength(2);
    expect(screen.getByText("beta.example.com")).toBeInTheDocument();

    await user.type(
      screen.getByPlaceholderText(
        "Search domains, certificate refs, request IDs, status, targets, or credentials",
      ),
      "beta",
    );

    await waitFor(() => {
      const rows = screen.getAllByTestId("deployment-row");
      expect(rows).toHaveLength(1);
      expect(rows[0]).toHaveTextContent("beta.example.com");
    });
  });

  it("opens deploy dialog from query and clears one-time query param", async () => {
    searchParamsValue =
      "domain=alpha.example.com&deployCertificateXref=cert-777";
    currentPermissions = ["deployments:view", "certificate:deploy"];
    server.use(
      http.get(`${API_BASE_URL}/api/v1/deployments`, () =>
        HttpResponse.json({
          items: [],
          page: 0,
          size: 0,
          totalItems: 0,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    await screen.findByText("No deployments found for the current filters.");
    await waitFor(() =>
      expect(replaceMock).toHaveBeenCalledWith(
        "/cert-manager/deployments/101?domain=alpha.example.com",
      ),
    );
  });

  it("groups failed statuses when statusGroup filter is set", async () => {
    searchParamsValue = "domain=alpha.example.com&statusGroup=failed";
    currentPermissions = ["deployments:view", "certificate:deploy"];
    server.use(
      http.get(`${API_BASE_URL}/api/v1/deployments`, () =>
        HttpResponse.json({
          items: [
            {
              id: 1,
              requestId: "req-ok",
              userDomainCertId: 101,
              domain: "ok.example.com",
              status: "COMPLETED",
              targetType: "AKAMAI",
              flowType: "MANUAL",
            },
            {
              id: 2,
              requestId: "req-failed",
              userDomainCertId: 101,
              domain: "bad.example.com",
              status: "FAILED_DEPLOYMENT",
              targetType: "CLOUDFLARE",
              flowType: "MANUAL",
            },
          ],
          page: 0,
          size: 2,
          totalItems: 2,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(await screen.findByText("bad.example.com")).toBeInTheDocument();
    expect(screen.queryByText("ok.example.com")).not.toBeInTheDocument();
  });
});
