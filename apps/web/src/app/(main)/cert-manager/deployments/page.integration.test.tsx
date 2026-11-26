// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import CertificateDeploymentsPage from "@/app/(main)/cert-manager/deployments/page";
import { useAuthStore } from "@/stores/auth-store";
import { seedFeatureFlags } from "@/test/feature-flags";
import { server } from "@/test/msw/server";

const replaceMock = jest.fn();
const pushMock = jest.fn();
let mockSearchParams = "";
let mockAuthState = {
  user: {
    id: "user-1",
    email: "user@example.com",
    organizationId: "org-1",
    organizationName: "Org",
    roles: ["USER"],
    permissions: ["deployments:view", "certificate:deploy"],
    authMethod: "LOCAL" as const,
  },
  isSuperAdmin: false,
  isLoading: false,
};

jest.mock("next/navigation", () => ({
  useRouter: () => ({
    replace: replaceMock,
    push: pushMock,
  }),
  usePathname: () => "/cert-manager/deployments",
  useSearchParams: () => new URLSearchParams(mockSearchParams),
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
jest.mock("@/components/ui/custom-table", () => ({
  CustomTable: ({
    data,
    onSearchTermChange,
  }: {
    data: Array<{ domain: string }>;
    onSearchTermChange?: (value: string) => void;
  }) => {
    const [term, setTerm] = React.useState("");
    const visible = data.filter((row) =>
      row.domain.toLowerCase().includes(term.toLowerCase()),
    );

    return (
      <div>
        <input
          placeholder="Search domains"
          value={term}
          onChange={(event) => {
            setTerm(event.target.value);
            onSearchTermChange?.(event.target.value);
          }}
        />
        {visible.map((row) => (
          <div key={row.domain}>{row.domain}</div>
        ))}
      </div>
    );
  },
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuthState,
}));
jest.mock("@/components/common/unautorised", () => ({
  Unauthorised: () => <div>Access Restricted</div>,
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

function renderPage() {
  useAuthStore.setState({
    user: mockAuthState.user,
    isLoading: mockAuthState.isLoading,
    isSuperAdmin: mockAuthState.isSuperAdmin,
    expiresAt: Date.now() + 60_000,
  });

  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <CertificateDeploymentsPage />
    </QueryClientProvider>,
  );
}

describe("deployments page integration (UI + MSW)", () => {
  beforeEach(() => {
    // FeatureRouteGate only mounts this page once deployment is confirmed on.
    seedFeatureFlags({ CERTIFICATE_DEPLOYMENT: true });
    mockSearchParams = "";
    mockAuthState = {
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["deployments:view", "certificate:deploy"],
        authMethod: "LOCAL" as const,
      },
      isSuperAdmin: false,
      isLoading: false,
    };
    server.use(
      http.get(
        `${API_BASE_URL}/api/v1/deployments/user-domain-certs/summary`,
        () =>
          HttpResponse.json({
            items: [],
            page: 0,
            size: 0,
            totalItems: 0,
            totalPages: 1,
          }),
      ),
    );
  });

  afterEach(() => {
    server.resetHandlers();
    replaceMock.mockReset();
    pushMock.mockReset();
  });

  it("renders metrics and domain rows from deployment summaries", async () => {
    server.use(
      http.get(
        `${API_BASE_URL}/api/v1/deployments/user-domain-certs/summary`,
        () =>
          HttpResponse.json({
            items: [
              {
                userDomainCertId: 101,
                domain: "alpha.example.com",
                deploymentsRequested: 4,
                deploymentsSucceeded: 4,
                deploymentsFailed: 0,
              },
              {
                userDomainCertId: 202,
                domain: "beta.example.com",
                deploymentsRequested: 3,
                deploymentsSucceeded: 1,
                deploymentsFailed: 2,
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

    expect(await screen.findByText("alpha.example.com")).toBeInTheDocument();
    expect(screen.getByText("beta.example.com")).toBeInTheDocument();
    expect(screen.getByText(/domains:2/i)).toBeInTheDocument();
    expect(screen.getByText(/deployments:7/i)).toBeInTheDocument();
    expect(screen.getByText(/Healthy:1/i)).toBeInTheDocument();
    expect(screen.getByText(/need attention:1/i)).toBeInTheDocument();
  });

  it("calls out failed deployments, lists them first and filters to them", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(
        `${API_BASE_URL}/api/v1/deployments/user-domain-certs/summary`,
        () =>
          HttpResponse.json({
            items: [
              {
                userDomainCertId: 101,
                domain: "alpha.example.com",
                deploymentsRequested: 4,
                deploymentsSucceeded: 4,
                deploymentsFailed: 0,
              },
              {
                userDomainCertId: 202,
                domain: "beta.example.com",
                deploymentsRequested: 3,
                deploymentsSucceeded: 1,
                deploymentsFailed: 2,
              },
              {
                userDomainCertId: 303,
                domain: "gamma.example.com",
                deploymentsRequested: 1,
                deploymentsSucceeded: 0,
                deploymentsFailed: 1,
              },
            ],
            page: 0,
            size: 3,
            totalItems: 3,
            totalPages: 1,
          }),
      ),
    );

    renderPage();

    expect(
      await screen.findByText("2 domains have failed deployments"),
    ).toBeInTheDocument();
    const alpha = screen.getByText("alpha.example.com");
    const beta = screen.getByText("beta.example.com");
    const gamma = screen.getByText("gamma.example.com");
    expect(
      beta.compareDocumentPosition(gamma) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      gamma.compareDocumentPosition(alpha) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Show failed" }));
    expect(screen.queryByText("alpha.example.com")).not.toBeInTheDocument();
    expect(screen.getByText("beta.example.com")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show all domains" }));
    expect(screen.getByText("alpha.example.com")).toBeInTheDocument();
  });

  it("filters deployment rows by search term", async () => {
    const user = userEvent.setup();

    server.use(
      http.get(
        `${API_BASE_URL}/api/v1/deployments/user-domain-certs/summary`,
        () =>
          HttpResponse.json({
            items: [
              {
                userDomainCertId: 301,
                domain: "prod.example.com",
                deploymentsRequested: 2,
                deploymentsSucceeded: 2,
                deploymentsFailed: 0,
              },
              {
                userDomainCertId: 302,
                domain: "staging.example.com",
                deploymentsRequested: 2,
                deploymentsSucceeded: 1,
                deploymentsFailed: 1,
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

    expect(await screen.findByText("prod.example.com")).toBeInTheDocument();
    expect(screen.getByText("staging.example.com")).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText(/Search domains/i), "staging");

    await waitFor(() => {
      expect(screen.queryByText("prod.example.com")).not.toBeInTheDocument();
      expect(screen.getByText("staging.example.com")).toBeInTheDocument();
    });
  });

  it("shows empty state when deployment summaries are empty", async () => {
    server.use(
      http.get(
        `${API_BASE_URL}/api/v1/deployments/user-domain-certs/summary`,
        () =>
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
      await screen.findByText("No deployment domains yet"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Domains with deployment history will appear here once certificates are pushed to saved targets.",
      ),
    ).toBeInTheDocument();
  });

  it("shows unauthorized state when user cannot view deployments", async () => {
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: ["certificate:deploy"],
      },
    };

    renderPage();
    expect(await screen.findByText("Access Restricted")).toBeInTheDocument();
  });

  it("shows loading skeleton while auth is loading", () => {
    mockAuthState = {
      ...mockAuthState,
      isLoading: true,
    };

    const { container } = renderPage();
    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(
      0,
    );
  });

  it("removes deployCertificateXref from query after opening flow", async () => {
    mockSearchParams = "deployCertificateXref=cert-123&search=alpha";
    server.use(
      http.get(
        `${API_BASE_URL}/api/v1/deployments/user-domain-certs/summary`,
        () =>
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
    await screen.findByText("No deployment domains yet");
    expect(replaceMock).toHaveBeenCalledWith(
      "/cert-manager/deployments?search=alpha",
    );
  });
});
