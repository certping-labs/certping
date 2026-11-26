// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import DiscoveryPage from "@/app/(main)/cert-manager/discovery/page";
import { useAuthStore } from "@/stores/auth-store";
import { server } from "@/test/msw/server";
import type { DiscoveryRunResponse } from "@/types/discovery";

const API = process.env.NEXT_PUBLIC_API_URL as string;
const TRIGGER_URL = `${API}/api/v1/discovery/trigger`;

let mockPermissions: string[] = [];

const currentUser = () => ({
  id: "user-1",
  email: "user@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions: mockPermissions,
  authMethod: "LOCAL" as const,
});

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: jest.fn(), push: jest.fn() }),
  usePathname: () => "/cert-manager/discovery",
  useSearchParams: () => new URLSearchParams(""),
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({
    title,
    actions,
  }: {
    title: string;
    actions?: React.ReactNode;
  }) => (
    <div>
      <span>{title}</span>
      {actions}
    </div>
  ),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: currentUser(),
    isSuperAdmin: false,
    isLoading: false,
  }),
}));

const savedScan = (
  overrides: Partial<DiscoveryRunResponse>,
): DiscoveryRunResponse => ({
  configId: 301,
  status: "COMPLETE",
  message: "",
  requestId: "r-301",
  targetType: "AWS_ACM",
  credentialXref: "cred-aws-001",
  startedAt: "2026-06-24T10:00:00Z",
  completedAt: "2026-06-24T10:00:11Z",
  ...overrides,
});

function serveDiscovery(configs: DiscoveryRunResponse[]) {
  server.use(
    http.get(`${API}/api/v1/deployment-info`, () =>
      HttpResponse.json({ agentTransport: "GATEWAY" }),
    ),
    http.get(`${API}/api/v1/credentials`, () =>
      HttpResponse.json({ items: [], totalItems: 0 }),
    ),
    http.get(`${API}/api/v1/discovery/certs`, () =>
      HttpResponse.json({
        content: [],
        totalElements: 0,
        totalPages: 1,
        number: 0,
        size: 100,
      }),
    ),
    http.get(TRIGGER_URL, () => HttpResponse.json(configs)),
  );
}

function renderPage() {
  useAuthStore.setState({
    user: currentUser(),
    isLoading: false,
    isSuperAdmin: false,
    expiresAt: Date.now() + 60_000,
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <DiscoveryPage />
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

describe("discovery after the feature lifecycle changes", () => {
  it("shows a scan stopped by turning discovery off as cancelled, not failed", async () => {
    mockPermissions = ["certificate:read", "certificate:deploy"];
    serveDiscovery([savedScan({ status: "CANCELLED" })]);
    const user = renderPage();

    expect(
      await screen.findByText("Discovery scan status"),
    ).toBeInTheDocument();
    expect(screen.getByText("1 cancelled")).toBeInTheDocument();
    expect(screen.queryByText(/failed/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Show 1/ }));
    expect(await screen.findByText("Cancelled")).toBeInTheDocument();
    expect(screen.getByText("This scan was cancelled.")).toBeInTheDocument();
  });

  it("hides every scan control without certificate:deploy or certificate:delete", async () => {
    mockPermissions = ["certificate:read", "certificate:issue"];
    serveDiscovery([
      savedScan({ status: "FAILED", message: "Access denied." }),
    ]);
    renderPage();

    expect(
      await screen.findByText("Discovery scan status"),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(
        "Certificates appear here after a discovery scan runs.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Trigger scan/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Manage scan configs" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Manage" }),
    ).not.toBeInTheDocument();
  });

  it("lets a user with only certificate:delete remove saved scans but not run them", async () => {
    mockPermissions = ["certificate:read", "certificate:delete"];
    serveDiscovery([savedScan({})]);
    const user = renderPage();

    await user.click(
      await screen.findByRole("button", { name: "Manage scan configs" }),
    );
    const dialog = await screen.findByRole("dialog");

    expect(
      await within(dialog).findByRole("button", {
        name: "Remove discovery configuration",
      }),
    ).toBeInTheDocument();
    expect(
      within(dialog).queryByRole("button", { name: /^Run/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Trigger scan/ }),
    ).not.toBeInTheDocument();
  });

  it("lets a user with only certificate:deploy run saved scans but not remove them", async () => {
    mockPermissions = ["certificate:read", "certificate:deploy"];
    serveDiscovery([savedScan({})]);
    const user = renderPage();

    await user.click(
      await screen.findByRole("button", { name: "Manage scan configs" }),
    );
    const dialog = await screen.findByRole("dialog");

    expect(
      await within(dialog).findByRole("button", { name: "Run all" }),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("Complete")).toBeInTheDocument();
    expect(
      within(dialog).queryByRole("button", {
        name: "Remove discovery configuration",
      }),
    ).not.toBeInTheDocument();
  });
});
