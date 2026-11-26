// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import CertManagerPage from "@/app/(main)/cert-manager/page";
import { server } from "@/test/msw/server";

const replaceMock = jest.fn();
const pushMock = jest.fn();
let mockIsMobile = true;
let featureFlags: Record<string, boolean> = {};
let mockAuthState = {
  user: {
    id: "user-1",
    email: "user@example.com",
    organizationId: "org-1",
    organizationName: "Org",
    roles: ["USER"],
    permissions: [
      "certificate:read",
      "certificate:create",
      "certificate:deploy",
      "certificate:renew",
      "certificate:revoke",
      "certificate:delete",
      "credential:update",
    ],
    authMethod: "LOCAL",
  },
  isLoading: false,
  isSuperAdmin: false,
};

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock, push: pushMock }),
  usePathname: () => "/cert-manager",
  useSearchParams: () => new URLSearchParams(""),
}));

jest.mock("@/hooks/use-mobile", () => ({
  useIsMobile: () => mockIsMobile,
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuthState,
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) => featureFlags[key] !== false,
  useIsOrgFeatureEnabled: (key: string) => featureFlags[key] !== false,
}));

jest.mock("@/hooks/use-animated-count", () => ({
  useAnimatedCount: (target: number) => target,
}));

jest.mock("@/components/cert-manager/certificate-management-dialog", () => ({
  CertificateManagementDialog: ({
    open,
    certificate,
  }: {
    open: boolean;
    certificate: { domain?: string } | null;
  }) => (open ? <div>Manage automation for {certificate?.domain}</div> : null),
}));

jest.mock("@/components/cert-manager/manual-txt-records-dialog", () => ({
  ManualTxtRecordsDialog: () => null,
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

jest.mock("@/components/common/tooltip-card", () => ({
  ToolTipCard: ({
    children,
    value,
  }: {
    children: React.ReactNode;
    value?: React.ReactNode;
  }) => (
    <div>
      {children}
      {value}
    </div>
  ),
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({
    title,
    subtitle,
    actions,
  }: {
    title: string;
    subtitle?: string;
    actions?: React.ReactNode;
  }) => (
    <div>
      <div>{title}</div>
      {subtitle ? <div>{subtitle}</div> : null}
      {actions ? <div>{actions}</div> : null}
    </div>
  ),
}));

jest.mock("@/components/ui/custom-table", () => ({
  CustomTable: ({
    defaultSearchTerm,
    defaultFilterValues,
    onSearchTermChange,
    onFilterValuesChange,
    filters,
  }: {
    defaultSearchTerm?: string;
    defaultFilterValues?: Record<string, string>;
    onSearchTermChange?: (value: string) => void;
    onFilterValuesChange?: (value: Record<string, string>) => void;
    filters?: { id: string; options?: { label: string; value: string }[] }[];
  }) => (
    <div>
      <div>TABLE_VIEW</div>
      <div>
        status-options:
        {(filters?.find((filter) => filter.id === "status")?.options ?? [])
          .map((option) => `${option.value}=${option.label}`)
          .join("|")}
      </div>
      <div>search:{defaultSearchTerm}</div>
      <div>filters:{JSON.stringify(defaultFilterValues ?? {})}</div>
      <button type="button" onClick={() => onSearchTermChange?.("example")}>
        set-search
      </button>
      <button
        type="button"
        onClick={() => onFilterValuesChange?.({ status: "ACTIVE" })}
      >
        set-filter
      </button>
    </div>
  ),
}));

jest.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({
    children,
    onClick,
    asChild,
  }: {
    children: React.ReactNode;
    onClick?: () => void;
    asChild?: boolean;
  }) =>
    asChild ? (
      <div>{children}</div>
    ) : (
      <button type="button" onClick={onClick}>
        {children}
      </button>
    ),
}));
jest.mock("@/components/common/unautorised", () => ({
  Unauthorised: () => <div>Access Restricted</div>,
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <CertManagerPage />
    </QueryClientProvider>,
  );
}

describe("cert-manager page integration (UI + MSW)", () => {
  beforeEach(() => {
    featureFlags = {};
    mockIsMobile = true;
    mockAuthState = {
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: [
          "certificate:read",
          "certificate:create",
          "certificate:deploy",
          "certificate:renew",
          "certificate:revoke",
          "certificate:delete",
          "credential:update",
        ],
        authMethod: "LOCAL",
      },
      isLoading: false,
      isSuperAdmin: false,
    };
  });

  afterEach(() => {
    server.resetHandlers();
    replaceMock.mockReset();
    pushMock.mockReset();
  });

  it("renders certificates from API list", async () => {
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

    renderPage();

    expect(await screen.findByText("prod.example.com")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
  });

  it("filters certificates by search term in card view", async () => {
    const user = userEvent.setup();

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
            {
              certificateXref: "cert-2",
              domain: "staging.example.com",
              status: "PENDING",
              caProvider: "LETS_ENCRYPT",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 2,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    await screen.findByText("prod.example.com");
    await screen.findByText("staging.example.com");

    await user.type(
      screen.getByPlaceholderText(/Search by domain, provider or issuer/i),
      "staging",
    );

    await waitFor(() => {
      expect(screen.getByText("staging.example.com")).toBeInTheDocument();
      expect(screen.queryByText("prod.example.com")).not.toBeInTheDocument();
    });
  });

  it("shows empty state when no certificates are returned", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [],
          page: 0,
          size: 100,
          totalItems: 0,
          totalPages: 1,
        }),
      ),
    );

    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: [...mockAuthState.user.permissions, "certificate:issue"],
      },
    };
    renderPage();

    expect(await screen.findByText("No certificates yet.")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Issue a certificate" }),
    ).toHaveAttribute("href", "/cert-manager/add");
    expect(screen.queryByText(/Adjust the filters/i)).not.toBeInTheDocument();
  });

  it("keeps the filter-miss copy when a search hides every certificate", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-1",
              domain: "prod.example.com",
              status: "ACTIVE",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        }),
      ),
    );

    renderPage();
    await screen.findByText("prod.example.com");
    await user.type(
      screen.getByPlaceholderText(/Search by domain, provider or issuer/i),
      "nothing-matches",
    );

    expect(
      await screen.findByText(/No certificates found\. Adjust the filters/i),
    ).toBeInTheDocument();
    expect(screen.queryByText("No certificates yet.")).not.toBeInTheDocument();
  });

  it("offers no first issue when certificate issuance is switched off", async () => {
    featureFlags = { CERTIFICATE_ISSUANCE: false };
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: [...mockAuthState.user.permissions, "certificate:issue"],
      },
    };
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [],
          page: 0,
          size: 100,
          totalItems: 0,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(await screen.findByText("No certificates yet.")).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /Issue a certificate/ }),
    ).not.toBeInTheDocument();
  });

  it("lists failed certificates first without a reason the list does not carry", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-ok",
              domain: "ok.example.com",
              status: "ACTIVE",
              validTo: "2099-01-01T00:00:00Z",
            },
            {
              certificateXref: "cert-bad",
              domain: "bad.example.com",
              status: "FAILED",
              userMessage: "DNS validation timed out.",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 2,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    const failed = await screen.findByText("bad.example.com");
    const healthy = screen.getByText("ok.example.com");
    expect(
      failed.compareDocumentPosition(healthy) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      screen.queryByText("DNS validation timed out."),
    ).not.toBeInTheDocument();
  });

  it("shows unauthorized state when user cannot view certificates", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [],
          page: 0,
          size: 100,
          totalItems: 0,
          totalPages: 1,
        }),
      ),
    );
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: ["certificate:issue"],
      },
    };

    renderPage();

    expect(await screen.findByText("Access Restricted")).toBeInTheDocument();
  });

  it("shows loading skeleton while auth is loading", () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [],
          page: 0,
          size: 100,
          totalItems: 0,
          totalPages: 1,
        }),
      ),
    );
    mockAuthState = {
      ...mockAuthState,
      isLoading: true,
    };

    const { container } = renderPage();
    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(
      0,
    );
  });

  it("hides issue action when user lacks create permission", async () => {
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
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: mockAuthState.user.permissions.filter(
          (permission) => permission !== "certificate:create",
        ),
      },
    };

    renderPage();

    await screen.findByText("prod.example.com");
    expect(
      screen.queryByRole("link", { name: /Issue certificate/i }),
    ).not.toBeInTheDocument();
  });

  it("shows in-progress and failed statuses from API", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-1",
              domain: "pending.example.com",
              status: "AWAITING_DNS",
              caProvider: "DIGICERT",
            },
            {
              certificateXref: "cert-2",
              domain: "failed.example.com",
              status: "FAILED",
              caProvider: "DIGICERT",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 2,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(await screen.findByText("pending.example.com")).toBeInTheDocument();
    expect(screen.getByText("failed.example.com")).toBeInTheDocument();
    expect(screen.getByText("Awaiting DNS records")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });

  it("shows correct actions for an ACTIVE certificate when user has permissions", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-1",
              domain: "active.example.com",
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

    renderPage();

    expect(await screen.findByText("active.example.com")).toBeInTheDocument();
    expect(screen.getByText(/Deploy certificate/i)).toBeInTheDocument();
    expect(screen.getByText(/Renew certificate/i)).toBeInTheDocument();
    expect(screen.getByText(/Revoke certificate/i)).toBeInTheDocument();
    expect(screen.queryByText(/Delete certificate/i)).not.toBeInTheDocument();
  });

  it("hides deployment actions when certificate deployment is disabled", async () => {
    featureFlags = { CERTIFICATE_DEPLOYMENT: false };

    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-1",
              domain: "active.example.com",
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

    renderPage();

    expect(await screen.findByText("active.example.com")).toBeInTheDocument();
    expect(screen.queryByText(/Deploy certificate/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Renew certificate/i)).toBeInTheDocument();
  });

  it("shows delete action for FAILED certificates when allowed", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              userDomainCertId: "201",
              certificateXref: "cert-failed",
              domain: "failed.example.com",
              status: "FAILED",
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

    renderPage();

    expect(await screen.findByText("failed.example.com")).toBeInTheDocument();
    expect(screen.getByText(/Delete certificate/i)).toBeInTheDocument();
    expect(screen.queryByText(/Renew certificate/i)).not.toBeInTheDocument();
  });

  it("shows TXT-record view action only for manual certificates awaiting DNS", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-manual",
              domain: "dns.example.com",
              status: "AWAITING_DNS",
              managementState: "manual",
              caProvider: "DIGICERT",
            },
            {
              certificateXref: "cert-auto",
              domain: "auto.example.com",
              status: "AWAITING_DNS",
              dnsConfigXref: "cred-dns-1",
              caProvider: "DIGICERT",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 2,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(await screen.findByText("dns.example.com")).toBeInTheDocument();
    expect(screen.getAllByText(/View TXT records/i)).toHaveLength(1);
    // dns-managed should not expose manual DNS action.
    expect(screen.queryByText("auto.example.com")).toBeInTheDocument();
  });

  it("summarizes management state and automation actions across certificate variants", async () => {
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: Array.from(
          new Set([...mockAuthState.user.permissions, "credential:rotate"]),
        ),
      },
    };

    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-managed-1",
              domain: "managed.example.com",
              status: "ACTIVE",
              managementState: "fully-managed",
              dnsConfigXref: "dns-cred-1",
              deploymentCredentialXrefs: ["deploy-1"],
              caProvider: "DIGICERT",
            },
            {
              certificateXref: "cert-deploy-1",
              domain: "deploy.example.com",
              status: "ACTIVE",
              managementState: "deployment-managed",
              deploymentCredentialXrefs: ["deploy-1", "deploy-2"],
              caProvider: "DIGICERT",
            },
            {
              certificateXref: "cert-manual-1",
              domain: "manual.example.com",
              status: "PENDING",
              managementState: "manual",
              caProvider: "DIGICERT",
            },
            {
              certificateXref: "cert-dns-1",
              domain: "dns.example.com",
              status: "ACTIVE",
              managementState: "dns-managed",
              dnsConfigXref: "dns-cred-2",
              caProvider: "DIGICERT",
            },
            {
              certificateXref: "cert-enable-1",
              domain: "enable.example.com",
              status: "ACTIVE",
              managementState: "manual",
              caProvider: "DIGICERT",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 5,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(await screen.findByText("managed.example.com")).toBeInTheDocument();
    expect(await screen.findByText("deploy.example.com")).toBeInTheDocument();
    expect(await screen.findByText("manual.example.com")).toBeInTheDocument();
    expect(await screen.findByText("dns.example.com")).toBeInTheDocument();
    expect(await screen.findByText("enable.example.com")).toBeInTheDocument();

    const textContentEquals =
      (expected: string) => (_: string, element: Element | null) =>
        element?.textContent?.replace(/\\s+/g, " ").trim() === expected;

    expect(
      screen.getByText(textContentEquals("DNS + 1 deployment target")),
    ).toBeInTheDocument();
    expect(
      screen.getByText(textContentEquals("2 deployment targets attached")),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(/No saved DNS or deployment config/i).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getAllByText("Saved DNS credential attached").length,
    ).toBeGreaterThan(0);

    expect(screen.getAllByText("Enable automation").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Manage automation").length).toBeGreaterThan(0);
  });

  it("executes certificate action handlers deterministically (renew + revoke + delete + manage)", async () => {
    const user = userEvent.setup();
    let renewCalls = 0;

    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: Array.from(
          new Set([...mockAuthState.user.permissions, "credential:rotate"]),
        ),
      },
    };

    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-1",
              domain: "active.example.com",
              status: "ACTIVE",
              managementState: "manual",
              caProvider: "DIGICERT",
            },
            {
              userDomainCertId: "202",
              certificateXref: "cert-failed-1",
              domain: "failed.example.com",
              status: "FAILED",
              managementState: "manual",
              caProvider: "DIGICERT",
            },
            {
              certificateXref: "cert-unknown",
              domain: "unknown.example.com",
              status: "UNKNOWN_STATUS",
              caProvider: "DIGICERT",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 3,
          totalPages: 1,
        }),
      ),
      http.post(
        `${API_BASE_URL}/api/v1/certs/:certificateXref/renew`,
        ({ params }) => {
          renewCalls += 1;
          return HttpResponse.json({
            certificateXref: params.certificateXref,
            domain: "active.example.com",
            status: "PENDING",
          });
        },
      ),
    );

    renderPage();
    expect(await screen.findByText("active.example.com")).toBeInTheDocument();
    expect(await screen.findByText("failed.example.com")).toBeInTheDocument();
    expect(await screen.findByText("unknown.example.com")).toBeInTheDocument();

    // Renew triggers a POST; we assert deterministically via call counter.
    await user.click(
      screen.getByRole("button", { name: /Renew certificate/i }),
    );
    await waitFor(() => expect(renewCalls).toBe(1));

    // Manage automation opens the management dialog (rendered by our mock).
    await user.click(
      screen.getByRole("button", { name: /Enable automation/i }),
    );
    expect(
      await screen.findByText(/Manage automation for active\.example\.com/i),
    ).toBeInTheDocument();

    // Revoke opens confirm dialog.
    await user.click(
      screen.getByRole("button", { name: /Revoke certificate/i }),
    );
    expect(
      await screen.findByRole("heading", { name: "Revoke certificate?" }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Cancel/i }));

    // Delete opens confirm dialog.
    const deleteButtons = screen.getAllByRole("button", {
      name: /Delete certificate/i,
    });
    await user.click(deleteButtons[0]!);
    expect(
      await screen.findByRole("heading", { name: "Delete certificate?" }),
    ).toBeInTheDocument();
  });

  it("renders desktop table view when not mobile", async () => {
    mockIsMobile = false;

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

    renderPage();

    expect(await screen.findByText("TABLE_VIEW")).toBeInTheDocument();
    expect(screen.getByText("certificates:1")).toBeInTheDocument();
  });

  it("calls out certificates that failed to issue and links to them", async () => {
    mockIsMobile = false;
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            {
              certificateXref: "cert-1",
              domain: "broken.example.com",
              status: "FAILED",
              caProvider: "LETS_ENCRYPT",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(
      await screen.findByText("1 certificate failed to issue"),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Show failed" })).toHaveAttribute(
      "href",
      "/cert-manager?status=FAILED",
    );
  });

  it("counts failed certificates in the callout without per-reason grouping", async () => {
    mockIsMobile = false;
    const failed = (id: string, userMessage: string) => ({
      certificateXref: id,
      domain: `${id}.example.com`,
      status: "FAILED",
      userMessage,
    });
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [
            failed("a", "DNS validation timed out."),
            failed("b", "CAA record forbids this CA."),
            failed("c", "DNS validation timed out."),
          ],
          page: 0,
          size: 100,
          totalItems: 3,
          totalPages: 1,
        }),
      ),
    );

    renderPage();

    expect(
      await screen.findByText("3 certificates failed to issue"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/DNS validation timed out/),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Show these" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Show failed" })).toHaveAttribute(
      "href",
      "/cert-manager?status=FAILED",
    );
  });

  it("offers only backend certificate statuses as table filters", async () => {
    mockIsMobile = false;
    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [],
          page: 0,
          size: 100,
          totalItems: 0,
          totalPages: 0,
        }),
      ),
    );

    renderPage();

    const options = await screen.findByText(/^status-options:/);
    expect(options).toHaveTextContent("AWAITING_DNS=Awaiting DNS records");
    expect(options).toHaveTextContent("PENDING_DNS=Preparing DNS records");
    expect(options.textContent).not.toMatch(/ISSUING|DEPLOYING/);
  });

  it("renders the first certificate page while later pages load", async () => {
    mockIsMobile = false;
    const requestedPages: string[] = [];

    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, ({ request }) => {
        const page = new URL(request.url).searchParams.get("page") ?? "0";
        requestedPages.push(page);
        return HttpResponse.json({
          items: [
            {
              certificateXref: `cert-${page}`,
              domain: `${page}.example.com`,
              status: "ACTIVE",
              caProvider: "DIGICERT",
            },
          ],
          page: Number(page),
          size: 100,
          totalItems: 2,
          totalPages: 2,
        });
      }),
    );

    renderPage();

    expect(await screen.findByText("TABLE_VIEW")).toBeInTheDocument();
    expect(screen.getByText("certificates:1")).toBeInTheDocument();
    expect(await screen.findByText("1 of 2")).toBeVisible();

    await waitFor(() => {
      expect(screen.getByText("certificates:2")).toBeInTheDocument();
      expect(
        screen.queryByText("Loading certificate inventory"),
      ).not.toBeInTheDocument();
    });
    expect(requestedPages).toEqual(["0", "1"]);
  });

  it("keeps table search local and syncs filter state into the URL", async () => {
    mockIsMobile = false;
    const user = userEvent.setup();

    server.use(
      http.get(`${API_BASE_URL}/api/v1/certs`, () =>
        HttpResponse.json({
          items: [],
          page: 0,
          size: 100,
          totalItems: 0,
          totalPages: 0,
        }),
      ),
    );

    renderPage();
    expect(await screen.findByText("TABLE_VIEW")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "set-search" }));
    expect(replaceMock).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "set-filter" }));
    await waitFor(() =>
      expect(replaceMock).toHaveBeenCalledWith("/cert-manager?status=ACTIVE", {
        scroll: false,
      }),
    );
  });
});
