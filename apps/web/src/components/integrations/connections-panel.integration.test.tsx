// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import { ConnectionsPanel } from "@/components/integrations/connections-panel";
import { useAuthStore } from "@/stores/auth-store";
import { findFeatureRouteRule } from "@/lib/feature-routes";
import { server } from "@/test/msw/server";

const replaceMock = jest.fn();
const pushMock = jest.fn();
let featureFlags: Record<string, boolean> = {};
let mockAuthState = {
  user: {
    id: "user-1",
    email: "user@example.com",
    organizationId: "org-1",
    organizationName: "Org",
    roles: ["USER"],
    permissions: [
      "credential:read",
      "credential:create",
      "credential:rotate",
      "credential:delete",
    ],
    authMethod: "LOCAL",
  },
  isSuperAdmin: false,
  isLoading: false,
};

jest.mock("next/navigation", () => ({
  useRouter: () => ({
    replace: replaceMock,
    push: pushMock,
  }),
  usePathname: () => "/integrations/deployment-targets",
  useSearchParams: () =>
    new URLSearchParams("tab=DEPLOYMENT&search=&status=all"),
}));

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img alt={props.alt ?? ""} {...props} />
  ),
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({ title }: { title: string }) => <div>{title}</div>,
}));

type MockCredential = {
  credentialXref?: string;
  alias?: string;
  description?: string;
  providerName?: string;
};

jest.mock("@/components/cert-manager/credential-details-dialog", () => ({
  CredentialDetailsDialog: ({
    credential,
    open,
    onClose,
    onDelete,
  }: {
    credential: MockCredential | null;
    open: boolean;
    onClose: () => void;
    onDelete?: (credential: MockCredential) => void;
  }) =>
    open && credential ? (
      <dialog aria-label="Credential details" open>
        <button type="button" onClick={onClose}>
          Close details
        </button>
        <button type="button" onClick={() => onDelete?.(credential)}>
          Delete from details
        </button>
      </dialog>
    ) : null,
  getCredentialStatusBadgeVariant: () => "secondary",
  getCredentialTitle: (credential: { description?: string; alias?: string }) =>
    credential.description || credential.alias || "Credential",
  getCredentialSubtitle: (credential: { providerName?: string }) =>
    credential.providerName || "Provider",
}));

jest.mock("@/components/common/provider-icon", () => ({
  ProviderIcon: ({ provider }: { provider: string }) => <div>{provider}</div>,
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuthState,
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) => featureFlags[key] !== false,
  useIsOrgFeatureEnabled: (key: string) => featureFlags[key] !== false,
}));

jest.mock("@/components/common/unautorised", () => ({
  Unauthorised: () => <div>Access Restricted</div>,
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
  DropdownMenuItem: ({
    children,
    onClick,
  }: {
    children: React.ReactNode;
    onClick?: () => void;
  }) => (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  ),
}));

const SelectContext = React.createContext<{
  value?: string;
  onValueChange?: (value: string) => void;
} | null>(null);

jest.mock("@/components/ui/select", () => ({
  Select: ({
    value,
    onValueChange,
    children,
  }: {
    value?: string;
    onValueChange?: (value: string) => void;
    children: React.ReactNode;
  }) => (
    <SelectContext.Provider value={{ value, onValueChange }}>
      <div>{children}</div>
    </SelectContext.Provider>
  ),
  SelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <button type="button">{children}</button>
  ),
  SelectValue: ({ placeholder }: { placeholder?: string }) => (
    <span>{placeholder ?? ""}</span>
  ),
  SelectContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  SelectItem: ({
    value,
    children,
  }: {
    value: string;
    children: React.ReactNode;
  }) => {
    const ctx = React.useContext(SelectContext);
    return (
      <button type="button" onClick={() => ctx?.onValueChange?.(value)}>
        {children}
      </button>
    );
  },
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

function renderPage(type: "DNS" | "DEPLOYMENT" = "DEPLOYMENT") {
  useAuthStore.setState({
    user: {
      id: "user-1",
      email: "user@example.com",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: [
        "credential:read",
        "credential:create",
        "credential:rotate",
        "credential:delete",
      ],
      authMethod: "LOCAL",
    },
    isLoading: false,
    isSuperAdmin: false,
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
      <ConnectionsPanel type={type} />
    </QueryClientProvider>,
  );
}

describe("connections panel integration (UI + MSW)", () => {
  beforeEach(() => {
    featureFlags = {};
    mockAuthState = {
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: [
          "credential:read",
          "credential:create",
          "credential:rotate",
          "credential:delete",
        ],
        authMethod: "LOCAL",
      },
      isSuperAdmin: false,
      isLoading: false,
    };
  });

  afterEach(() => {
    server.resetHandlers();
    replaceMock.mockReset();
    pushMock.mockReset();
  });

  it("renders deployment targets returned by backend reference API", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () => {
        return HttpResponse.json({
          items: [
            {
              credentialXref: "cred-dns-1",
              provider: "CLOUDFLARE",
              type: "DNS",
              description: "Cloudflare DNS",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/cloudflare",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
            {
              credentialXref: "cred-deploy-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Akamai Edge Prod",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        });
      }),
    );

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("Akamai Edge Prod")).toBeInTheDocument();
      expect(screen.getByText("cred-deploy-1")).toBeInTheDocument();
      expect(screen.getByText("ACTIVE")).toBeInTheDocument();
    });
  });

  it("hides deployment credentials when certificate deployment is disabled", async () => {
    featureFlags = {
      CERTIFICATE_DEPLOYMENT: false,
    };

    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-deploy-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Akamai Edge Prod",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
            {
              credentialXref: "cred-dns-1",
              provider: "CLOUDFLARE",
              type: "DNS",
              description: "Cloudflare DNS",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/cloudflare",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 2,
        }),
      ),
    );

    // A bookmark to Deployment Targets is refused by FeatureRouteGate (see
    // feature-route-gate.integration.test); the panel itself only has to keep
    // deployment credentials out of every other category.
    expect(
      findFeatureRouteRule("/integrations/deployment-targets")?.features,
    ).toContain("CERTIFICATE_DEPLOYMENT");

    renderPage("DNS");
    expect(await screen.findByText("Cloudflare DNS")).toBeInTheDocument();
    expect(screen.queryByText("Akamai Edge Prod")).not.toBeInTheDocument();
  });

  it("keeps DNS providers listed but offers no add, edit or delete while DNS credentials are off", async () => {
    featureFlags = { DNS_CREDENTIALS: false };
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-dns-1",
              provider: "CLOUDFLARE",
              type: "DNS",
              description: "Cloudflare DNS",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/cloudflare",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage("DNS");

    const row = (await screen.findByText("Cloudflare DNS")).closest("tr");
    expect(row).not.toBeNull();
    expect(
      within(row as HTMLElement).queryByRole("button", {
        name: /Open credential actions/i,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Connect DNS provider/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Connecting DNS providers isn't available. Ask your CertPing administrator.",
      ),
    ).toBeInTheDocument();
  });

  it("still lets deployment targets be added and edited while DNS credentials are off", async () => {
    featureFlags = { DNS_CREDENTIALS: false };
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-deploy-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Akamai Edge Prod",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage("DEPLOYMENT");

    const row = (await screen.findByText("Akamai Edge Prod")).closest("tr");
    expect(
      within(row as HTMLElement).getByRole("button", {
        name: /Open credential actions/i,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Add deployment target/i }),
    ).toBeInTheDocument();
  });

  it("filters the open category by search query", async () => {
    const user = userEvent.setup();

    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-deploy-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Akamai Edge Prod",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
            {
              credentialXref: "cred-deploy-2",
              provider: "F5_BIGIP",
              type: "DEPLOYMENT",
              description: "F5 Internal",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/f5",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 2,
        }),
      ),
    );

    renderPage();

    await screen.findByText("Akamai Edge Prod");
    await screen.findByText("F5 Internal");

    await user.type(
      screen.getByPlaceholderText(
        /Search deployment targets, references, or secret handles/i,
      ),
      "F5",
    );

    await waitFor(() => {
      expect(screen.getByText("F5 Internal")).toBeInTheDocument();
      expect(screen.queryByText("Akamai Edge Prod")).not.toBeInTheDocument();
    });
  });

  it("closes credential details before opening delete confirmation", async () => {
    const user = userEvent.setup();

    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-deploy-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Akamai Edge Prod",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage();
    await user.click(
      await screen.findByRole("button", { name: /Akamai Edge Prod/i }),
    );

    expect(
      await screen.findByRole("dialog", { name: "Credential details" }),
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Delete from details" }),
    );

    expect(
      screen.queryByRole("dialog", { name: "Credential details" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Delete Akamai Edge Prod\?/i)).toBeInTheDocument();
  });

  it("shows unauthorized state when user cannot view credentials", async () => {
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: ["credential:create"],
      },
    };

    renderPage();
    expect(await screen.findByText("Access Restricted")).toBeInTheDocument();
  });

  it("shows loading skeleton while auth is loading", () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [],
          totalItems: 0,
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

  it("shows inactive-warning when no active connections exist", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-deploy-2",
              provider: "F5_BIGIP",
              type: "DEPLOYMENT",
              description: "F5 Internal",
              status: "PENDING_ROTATION",
              secretHandle: "https://vault/secrets/f5",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage();
    expect(
      await screen.findByText("No active deployment targets"),
    ).toBeInTheDocument();
  });

  it("hides add action when user lacks create permission", async () => {
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...mockAuthState.user,
        permissions: mockAuthState.user.permissions.filter(
          (permission) => permission !== "credential:create",
        ),
      },
    };
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-deploy-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Akamai Edge Prod",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage();
    await screen.findByText("Deployment Targets");
    expect(
      screen.queryByRole("button", { name: /Add deployment target/i }),
    ).not.toBeInTheDocument();
  });

  it("shows 'No credentials yet' when backend returns empty list", async () => {
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({ items: [], totalItems: 0 }),
      ),
    );

    renderPage();
    expect(
      await screen.findByText("No deployment targets connected"),
    ).toBeInTheDocument();
  });

  it("filters credentials by status selector", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Active cred",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
            {
              credentialXref: "cred-2",
              provider: "F5_BIGIP",
              type: "DEPLOYMENT",
              description: "Inactive cred",
              status: "PENDING_ROTATION",
              secretHandle: "https://vault/secrets/f5",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 2,
        }),
      ),
    );

    renderPage();

    expect(await screen.findByText("Active cred")).toBeInTheDocument();
    expect(screen.getByText("Inactive cred")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /All statuses/i }));
    await user.click(screen.getByRole("button", { name: /^Active$/i }));

    await waitFor(() => {
      expect(screen.getByText("Active cred")).toBeInTheDocument();
      expect(screen.queryByText("Inactive cred")).not.toBeInTheDocument();
    });
  });

  it("navigates to edit page for non-k8s credentials", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-edit-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Editable cred",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage();
    await screen.findByText("Editable cred");

    const credentialRow = screen.getByText("Editable cred").closest("tr");
    expect(credentialRow).not.toBeNull();

    const actionsTrigger = within(credentialRow as HTMLElement).getByRole(
      "button",
      { name: /Open credential actions/i },
    );
    actionsTrigger.focus();
    await user.keyboard("{Enter}");

    await user.click(await screen.findByText(/^Update$/i));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith(
        "/integrations/connections/cred-edit-1/edit",
      );
    });
  });

  it("navigates to edit page for AKAMAI credentials", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-edit-url-1",
              provider: "AKAMAI_CPS",
              type: "DEPLOYMENT",
              description: "Editable cred",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/akamai",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage();
    await screen.findByText("Editable cred");

    const credentialRow = screen.getByText("Editable cred").closest("tr");
    expect(credentialRow).not.toBeNull();

    const actionsTrigger = within(credentialRow as HTMLElement).getByRole(
      "button",
      { name: /Open credential actions/i },
    );
    actionsTrigger.focus();
    await user.keyboard("{Enter}");
    await user.click(await screen.findByText(/^Update$/i));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith(
        "/integrations/connections/cred-edit-url-1/edit",
      );
    });
  });

  it("navigates to edit page for kubernetes credentials", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-k8s-edit-1",
              provider: "KUBERNETES_SECRETS",
              type: "DEPLOYMENT",
              description: "K8s cred",
              status: "ACTIVE",
              configJson: JSON.stringify({
                authMethod: "SA_TOKEN",
                clusterName: "prod",
                namespaces: ["dev"],
              }),
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage();
    await screen.findByText("K8s cred");

    const credentialRow = screen.getByText("K8s cred").closest("tr");
    expect(credentialRow).not.toBeNull();

    const actionsTrigger = within(credentialRow as HTMLElement).getByRole(
      "button",
      { name: /Open credential actions/i },
    );
    actionsTrigger.focus();
    await user.keyboard("{Enter}");
    await user.click(await screen.findByText(/^Update$/i));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith(
        "/integrations/connections/cred-k8s-edit-1/edit",
      );
    });
  });

  it("navigates to edit page for in-cluster kubernetes credential", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(`${API_BASE_URL}/api/v1/credentials`, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-k8s-1",
              provider: "KUBERNETES_SECRETS",
              type: "DEPLOYMENT",
              description: "K8s cred",
              status: "ACTIVE",
              configJson: JSON.stringify({
                authMethod: "SA_INCLUSTER",
                clusterName: "prod",
                namespaces: "all_namespaces",
              }),
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
    );

    renderPage();
    await screen.findByText("K8s cred");

    const credentialRow = screen.getByText("K8s cred").closest("tr");
    expect(credentialRow).not.toBeNull();

    const actionsTrigger = within(credentialRow as HTMLElement).getByRole(
      "button",
      { name: /Open credential actions/i },
    );
    actionsTrigger.focus();
    await user.keyboard("{Enter}");

    await user.click(await screen.findByText(/^Update$/i));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith(
        "/integrations/connections/cred-k8s-1/edit",
      );
    });
  });
});
