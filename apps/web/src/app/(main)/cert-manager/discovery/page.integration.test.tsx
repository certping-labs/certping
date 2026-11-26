// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import DiscoveryPage from "@/app/(main)/cert-manager/discovery/page";
import { useAuthStore } from "@/stores/auth-store";
import { server } from "@/test/msw/server";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;

const DISCOVERY_URL = `${API_BASE_URL}/api/v1/discovery/certs`;
const TRIGGER_URL = `${API_BASE_URL}/api/v1/discovery/trigger`;
const CREDENTIALS_URL = `${API_BASE_URL}/api/v1/credentials`;
const DEPLOYMENT_INFO_URL = `${API_BASE_URL}/api/v1/deployment-info`;

const baseUser = {
  id: "user-1",
  email: "user@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions: [
    "certificate:read",
    "certificate:issue",
    "certificate:deploy",
    "credential:read",
  ],
  authMethod: "LOCAL" as const,
};

let mockAuthState = {
  user: baseUser,
  isSuperAdmin: false,
  isLoading: false,
};

const mockPush = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: jest.fn(), push: mockPush }),
  usePathname: () => "/cert-manager/discovery",
  useSearchParams: () => new URLSearchParams(""),
}));

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img {...props} alt={props.alt ?? ""} />
  ),
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

jest.mock("@/components/common/unautorised", () => ({
  Unauthorised: () => <div>Access Restricted</div>,
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuthState,
}));

let mockIssuanceEnabled = true;
let mockFlagOverrides: Record<string, boolean> = {};
jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) =>
    key === "CERTIFICATE_ISSUANCE"
      ? mockIssuanceEnabled
      : (mockFlagOverrides[key] ?? true),
  useIsOrgFeatureEnabled: (key: string) =>
    key === "CERTIFICATE_ISSUANCE"
      ? mockIssuanceEnabled
      : (mockFlagOverrides[key] ?? true),
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

const makeCert = (
  overrides: Partial<{
    id: number;
    domain: string;
    certStatus: string;
    keyAlgorithm: string;
    managed: boolean | null;
    managedCertificateXref: string | null;
    credentialXref: string | null;
    notAfter: string;
    targetType: string;
    discoveredAt: string;
  }> = {},
) => ({
  id: overrides.id ?? 1,
  organizationId: 2,
  targetType: overrides.targetType ?? "AWS_ACM",
  resourceId: `arn:aws:acm:us-east-1:123:certificate/${overrides.id ?? 1}`,
  domain: overrides.domain ?? "example.example.net",
  keyAlgorithm: overrides.keyAlgorithm ?? "RSA_2048",
  signatureAlgorithm: "SHA256WITHRSA",
  notBefore: "2026-01-01T00:00:00Z",
  notAfter: overrides.notAfter ?? "2027-01-01T00:00:00Z",
  issuer: "Amazon",
  serialNumber: "aa:bb",
  certStatus: overrides.certStatus ?? "ISSUED",
  inUseBy: [],
  subjectDn: `CN=${overrides.domain ?? "example.example.net"}`,
  sanDomains: [overrides.domain ?? "example.example.net"],
  keyUsage: "ANY",
  extendedKeyUsage: null,
  certType: "AMAZON_ISSUED",
  managed: overrides.managed === undefined ? false : overrides.managed,
  managedCertificateXref: overrides.managedCertificateXref ?? null,
  credentialXref: overrides.credentialXref ?? null,
  discoveredAt: overrides.discoveredAt ?? "2026-05-06T22:00:00Z",
});

const makePage = (certs: ReturnType<typeof makeCert>[]) => ({
  content: certs,
  totalElements: certs.length,
  totalPages: 1,
  number: 0,
  size: 100,
});

function renderPage() {
  useAuthStore.setState({
    user: mockAuthState.user,
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
      <DiscoveryPage />
    </QueryClientProvider>,
  );
}

describe("DiscoveryPage integration (UI + MSW)", () => {
  beforeEach(() => {
    mockPush.mockClear();
    mockIssuanceEnabled = true;
    mockFlagOverrides = {};
    mockAuthState = { user: baseUser, isSuperAdmin: false, isLoading: false };
    server.use(
      http.get(DEPLOYMENT_INFO_URL, () =>
        HttpResponse.json({ agentTransport: "GATEWAY" }),
      ),
      http.get(CREDENTIALS_URL, () =>
        HttpResponse.json({ items: [], totalItems: 0 }),
      ),
      // Saved discovery configs list (drives the in-progress banner). Default to
      // none running; tests that need an active scan override this.
      http.get(TRIGGER_URL, () => HttpResponse.json([])),
    );
  });

  afterEach(() => {
    server.resetHandlers();
    window.sessionStorage.clear();
  });

  it("renders discovered certificates from backend", async () => {
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json(
          makePage([
            makeCert({
              id: 1,
              domain: "example.example.net",
              certStatus: "ISSUED",
            }),
            makeCert({
              id: 2,
              domain: "test2.example.net",
              certStatus: "EXPIRED",
            }),
          ]),
        ),
      ),
    );

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("example.example.net")).toBeInTheDocument();
      expect(screen.getByText("test2.example.net")).toBeInTheDocument();
    });
    expect(screen.getByText("Issued", { selector: "div" })).toBeInTheDocument();
    expect(
      screen.getByText("Expired", { selector: "div" }),
    ).toBeInTheDocument();
  });

  it("requests the discovery inventory in 100-row backend batches", async () => {
    const requestedParams: string[] = [];
    server.use(
      http.get(DISCOVERY_URL, ({ request }) => {
        const url = new URL(request.url);
        requestedParams.push(url.searchParams.toString());
        return HttpResponse.json(makePage([makeCert({ id: 1 })]));
      }),
    );

    renderPage();

    await screen.findByText("example.example.net");
    await waitFor(() => {
      expect(requestedParams).toContain("page=0&size=100");
    });
  });

  it("renders the credential xref under the source as a deep link", async () => {
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json(
          makePage([
            makeCert({
              id: 1,
              domain: "example.example.net",
              credentialXref: "cred-255081270228850",
            }),
          ]),
        ),
      ),
    );

    renderPage();

    const credLink = await screen.findByRole("link", {
      name: /cred-255081270228850/i,
    });
    expect(credLink).toHaveAttribute(
      "href",
      "/integrations/deployment-targets?credential=cred-255081270228850",
    );
  });

  it("shows empty state when no certificates are returned", async () => {
    server.use(http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))));

    renderPage();

    expect(
      await screen.findByText("No discovered certificates yet"),
    ).toBeInTheDocument();
  });

  it("shows access restricted when user lacks certificate:read", async () => {
    mockAuthState = {
      ...mockAuthState,
      user: { ...baseUser, permissions: ["credential:read"] },
    };

    renderPage();
    expect(await screen.findByText("Access Restricted")).toBeInTheDocument();
  });

  it("shows loading skeleton while auth is loading", () => {
    server.use(http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))));
    mockAuthState = { ...mockAuthState, isLoading: true };

    const { container } = renderPage();
    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(
      0,
    );
  });

  it("displays RSA_2048 key algorithm for discovered certs", async () => {
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json(
          makePage([makeCert({ id: 1, keyAlgorithm: "RSA_2048" })]),
        ),
      ),
    );

    renderPage();
    expect(await screen.findByText("RSA_2048")).toBeInTheDocument();
  });

  it("shows the source account/region derived from the resource id", async () => {
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json(makePage([makeCert({ id: 1 })])),
      ),
    );

    renderPage();
    // makeCert id=1 → arn:aws:acm:us-east-1:123:certificate/1
    expect(await screen.findByText("123 · us-east-1")).toBeInTheDocument();
  });

  it("shows managed / unmanaged / unknown states for discovered certs", async () => {
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json(
          makePage([
            makeCert({ id: 1, managed: true }),
            makeCert({ id: 2, managed: false }),
            makeCert({ id: 3, managed: null }),
          ]),
        ),
      ),
    );

    renderPage();
    await waitFor(() => {
      // "Managed" also appears in the column header, so expect at least 2 instances.
      expect(screen.getAllByText("Managed").length).toBeGreaterThanOrEqual(2);
      expect(screen.getByText("Unmanaged")).toBeInTheDocument();
      // managed === null renders as the not-yet-evaluated "Unknown" state.
      expect(screen.getAllByText("Unknown").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("links a managed cert's domain to its certificate detail page", async () => {
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json(
          makePage([
            makeCert({
              id: 1,
              domain: "managed.example.net",
              managed: true,
              managedCertificateXref: "cert-abc123",
            }),
            makeCert({
              id: 2,
              domain: "external.example.net",
              managed: false,
            }),
          ]),
        ),
      ),
    );

    renderPage();

    const managedLink = await screen.findByRole("link", {
      name: /managed\.example\.net/i,
    });
    expect(managedLink).toHaveAttribute(
      "href",
      "/cert-manager/manage/cert-abc123",
    );
    // External cert's domain is plain text, not a link.
    expect(
      screen.queryByRole("link", { name: /external\.example\.net/i }),
    ).not.toBeInTheDocument();
  });

  it("hides Trigger scan button when user lacks certificate:deploy", async () => {
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...baseUser,
        permissions: ["certificate:read", "credential:read"],
      },
    };
    server.use(http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))));

    renderPage();
    await screen.findByText("No discovered certificates yet");
    expect(
      screen.queryByRole("button", { name: /Trigger scan/i }),
    ).not.toBeInTheDocument();
  });

  describe("add deployment credential entry points", () => {
    const credentialCreator = {
      ...baseUser,
      permissions: [...baseUser.permissions, "credential:create"],
    };

    beforeEach(() => {
      mockAuthState = { ...mockAuthState, user: credentialCreator };
      server.use(
        http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
      );
    });

    it("links to adding a deployment credential when none exist", async () => {
      renderPage();

      const link = await screen.findByRole("link", {
        name: /Add deployment target/i,
      });
      expect(link).toHaveAttribute(
        "href",
        "/integrations/connections/add?type=DEPLOYMENT",
      );
    });

    it.each(["CREDENTIALS_MANAGEMENT", "CERTIFICATE_DEPLOYMENT"])(
      "hides the link when %s is off",
      async (flagKey) => {
        mockFlagOverrides = { [flagKey]: false };
        renderPage();

        const trigger = await screen.findByRole("button", {
          name: /Trigger scan/i,
        });
        expect(trigger).toBeDisabled();
        expect(
          screen.queryByRole("link", { name: /Add deployment target/i }),
        ).not.toBeInTheDocument();
      },
    );

    it("explains the missing credential:read instead of offering to add a credential", async () => {
      let credentialRequests = 0;
      server.use(
        http.get(CREDENTIALS_URL, () => {
          credentialRequests += 1;
          return HttpResponse.json({ items: [], totalItems: 0 });
        }),
      );
      mockAuthState = {
        ...mockAuthState,
        user: {
          ...baseUser,
          permissions: [
            "certificate:read",
            "certificate:deploy",
            "credential:create",
          ],
        },
      };
      renderPage();

      const trigger = await screen.findByRole("button", {
        name: /Trigger scan/i,
      });
      expect(trigger).toBeDisabled();
      expect(trigger).toHaveAttribute(
        "title",
        "You need permission to view credentials to start a scan. Ask an admin.",
      );
      expect(
        screen.queryByRole("link", { name: /Add deployment target/i }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByTitle("No credentials are configured for discovery"),
      ).not.toBeInTheDocument();
      expect(credentialRequests).toBe(0);
    });

    it("hides the link without the credential create permission", async () => {
      mockAuthState = { ...mockAuthState, user: baseUser };
      renderPage();

      await screen.findByRole("button", { name: /Trigger scan/i });
      expect(
        screen.queryByRole("link", { name: /Add deployment target/i }),
      ).not.toBeInTheDocument();
    });
  });

  it("omits the add-credential link from the trigger dialog when credential management is off", async () => {
    mockFlagOverrides = { CREDENTIALS_MANAGEMENT: false };
    mockAuthState = {
      ...mockAuthState,
      user: {
        ...baseUser,
        permissions: [...baseUser.permissions, "credential:create"],
      },
    };
    const user = userEvent.setup();
    server.use(
      http.get(CREDENTIALS_URL, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-aws-001",
              provider: "AWS_ACM",
              type: "DEPLOYMENT",
              description: "AWS Test",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/aws",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
      http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
    );

    renderPage();
    const triggerBtn = await screen.findByRole("button", {
      name: /Trigger scan/i,
    });
    await waitFor(() => expect(triggerBtn).not.toBeDisabled());
    await user.click(triggerBtn);

    expect(
      await screen.findByText("Trigger discovery scan"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /Add deployment target/i }),
    ).not.toBeInTheDocument();
  });

  it("opens trigger dialog with credential pre-selected", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(CREDENTIALS_URL, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-aws-001",
              provider: "AWS_ACM",
              type: "DEPLOYMENT",
              description: "AWS Test",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/aws",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
      http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
    );

    renderPage();

    // Wait for credentials to load so the trigger button becomes enabled
    const triggerBtn = await screen.findByRole("button", {
      name: /Trigger scan/i,
    });
    await waitFor(() => expect(triggerBtn).not.toBeDisabled());
    await user.click(triggerBtn);

    // Dialog opens
    expect(
      await screen.findByText("Trigger discovery scan"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Dispatches a scan for the selected deployment target/i),
    ).toBeInTheDocument();

    // Start scan button is present and enabled with credential pre-selected
    const startBtn = await screen.findByRole("button", { name: /Start scan/i });
    await waitFor(() => expect(startBtn).not.toBeDisabled());
  });

  it("shows Azure workload identity credentials for discovery", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(CREDENTIALS_URL, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-azure-wi",
              provider: "AZURE_KV",
              type: "DEPLOYMENT",
              description: "azure_kv_wi",
              status: "ACTIVE",
              configJson: JSON.stringify({
                authMode: "WORKLOAD_IDENTITY",
                vaultUri: "https://prod.vault.azure.net/",
                tenantId: "tenant-1",
              }),
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
      http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
    );

    renderPage();

    const triggerBtn = await screen.findByRole("button", {
      name: /Trigger scan/i,
    });
    await waitFor(() => expect(triggerBtn).not.toBeDisabled());
    await user.click(triggerBtn);

    expect(
      await screen.findByText("Trigger discovery scan"),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /Start scan/i }),
      ).not.toBeDisabled(),
    );
  });

  it("shows scan status after successful scan trigger", async () => {
    const user = userEvent.setup();
    // The configs list reflects the running scan only after it is dispatched.
    let dispatched = false;
    server.use(
      http.get(CREDENTIALS_URL, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-aws-001",
              provider: "AWS_ACM",
              type: "DEPLOYMENT",
              description: "AWS Test",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/aws",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
      http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
      http.get(TRIGGER_URL, () =>
        HttpResponse.json(
          dispatched
            ? [
                {
                  configId: 101,
                  status: "IN_PROGRESS",
                  targetType: "AWS_ACM",
                  credentialXref: "cred-aws-001",
                  message: "Discovery is still running.",
                  requestId: "disc-req-msw-1",
                  startedAt: "2026-06-24T10:00:00Z",
                  completedAt: null,
                },
              ]
            : [],
        ),
      ),
      http.post(TRIGGER_URL, () => {
        dispatched = true;
        return HttpResponse.json(
          {
            configId: 101,
            status: "STARTED",
            requestId: "disc-req-msw-1",
            targetType: "AWS_ACM",
            credentialXref: "cred-aws-001",
            message: "Discovery has started. Results will appear shortly.",
            startedAt: "2026-06-24T10:00:00Z",
            completedAt: null,
          },
          { status: 202 },
        );
      }),
    );

    renderPage();

    const triggerBtn = await screen.findByRole("button", {
      name: /Trigger scan/i,
    });
    await waitFor(() => expect(triggerBtn).not.toBeDisabled());
    await user.click(triggerBtn);
    await user.click(
      await screen.findByRole("button", { name: /Start scan/i }),
    );

    expect(
      await screen.findByText("Discovery scan status"),
    ).toBeInTheDocument();
    expect(await screen.findByText("In progress")).toBeInTheDocument();
    expect(
      await screen.findByText("Discovery is still running."),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/AWS Test/i).length).toBeGreaterThanOrEqual(1);
  });

  it("shows scan status from a running saved config on load", async () => {
    // Server-driven: a config already running (e.g. after a reload) surfaces the
    // banner without any client-side persistence.
    server.use(
      http.get(CREDENTIALS_URL, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-aws-001",
              provider: "AWS_ACM",
              type: "DEPLOYMENT",
              description: "AWS Test",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/aws",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
      http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
      http.get(TRIGGER_URL, () =>
        HttpResponse.json([
          {
            configId: 202,
            status: "IN_PROGRESS",
            targetType: "AWS_ACM",
            credentialXref: "cred-aws-001",
            message: "Discovery is still running.",
            requestId: "disc-req-running",
            startedAt: "2026-06-24T10:00:00Z",
            completedAt: null,
          },
        ]),
      ),
    );

    renderPage();

    expect(
      await screen.findByText("Discovery scan status"),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("Discovery is still running."),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/AWS Test/i).length).toBeGreaterThanOrEqual(1);
  });

  it("does not show scan status when no saved config needs attention", async () => {
    server.use(
      http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
      http.get(TRIGGER_URL, () =>
        HttpResponse.json([
          {
            configId: 303,
            status: "COMPLETE",
            targetType: "AWS_ACM",
            credentialXref: "cred-aws-001",
            message: "Discovery is complete.",
            requestId: "disc-req-done",
            startedAt: "2026-06-24T10:00:00Z",
            completedAt: "2026-06-24T10:00:11Z",
          },
        ]),
      ),
    );

    renderPage();

    await screen.findByText("No discovered certificates yet");
    expect(screen.queryByText("Discovery scan status")).not.toBeInTheDocument();
  });

  it("surfaces failed saved scan messages on the main page", async () => {
    server.use(
      http.get(CREDENTIALS_URL, () =>
        HttpResponse.json({
          items: [
            {
              credentialXref: "cred-k8s-001",
              provider: "KUBERNETES_SECRETS",
              type: "DEPLOYMENT",
              description: "Prod AKS",
              status: "ACTIVE",
              secretHandle: "https://vault/secrets/k8s",
              createdAt: "2026-01-01T00:00:00Z",
              updatedAt: "2026-01-02T00:00:00Z",
            },
          ],
          totalItems: 1,
        }),
      ),
      http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
      http.get(TRIGGER_URL, () =>
        HttpResponse.json([
          {
            configId: 404,
            status: "FAILED",
            targetType: "KUBERNETES_SECRETS",
            credentialXref: "cred-k8s-001",
            message:
              "Discovery failed because Kubernetes denied access to list Secrets.",
            requestId: "disc-req-failed",
            startedAt: "2026-06-24T10:00:00Z",
            completedAt: "2026-06-24T10:00:11Z",
          },
        ]),
      ),
    );

    renderPage();

    expect(
      await screen.findByText("Discovery scan status"),
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Show 1/i }));
    expect(
      await screen.findByText(
        "Discovery failed because Kubernetes denied access to list Secrets.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText("Kubernetes Secrets").length,
    ).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });

  it("navigates to the discovery detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json(
          makePage([
            makeCert({
              id: 7,
              domain: "k8s.example.net",
              targetType: "KUBERNETES_SECRETS",
            }),
          ]),
        ),
      ),
    );

    renderPage();

    await user.click(await screen.findByText("k8s.example.net"));

    expect(mockPush).toHaveBeenCalledWith("/cert-manager/discovery/7");
  });

  it("manages saved scans: lists configs and reruns one", async () => {
    const user = userEvent.setup();
    let reran = false;
    server.use(
      http.get(DISCOVERY_URL, () => HttpResponse.json(makePage([]))),
      http.get(TRIGGER_URL, () =>
        HttpResponse.json([
          {
            configId: 101,
            status: reran ? "STARTED" : "COMPLETE",
            targetType: "AWS_ACM",
            credentialXref: "cred-aws-001",
            message: reran
              ? "Discovery has started."
              : "Discovery is complete.",
            requestId: "r1",
            startedAt: "2026-06-24T10:00:00Z",
            completedAt: "2026-06-24T10:00:11Z",
          },
        ]),
      ),
      http.post(`${TRIGGER_URL}/:id`, () => {
        reran = true;
        return HttpResponse.json(
          {
            configId: 101,
            status: "STARTED",
            targetType: "AWS_ACM",
            credentialXref: "cred-aws-001",
            message: "Discovery has started.",
            requestId: "r2",
            startedAt: "2026-06-24T10:05:00Z",
            completedAt: null,
          },
          { status: 202 },
        );
      }),
    );

    renderPage();

    await user.click(
      await screen.findByRole("button", { name: /Manage scan configs/i }),
    );

    expect(
      await screen.findByText("Saved discovery scans"),
    ).toBeInTheDocument();
    expect(await screen.findByText("Complete")).toBeInTheDocument();
    expect(
      screen.queryByText("Discovery is complete."),
    ).not.toBeInTheDocument();

    await user.click(await screen.findByRole("button", { name: /^Run$/i }));

    expect(
      (await screen.findAllByText("Started")).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it("shows pagination controls when the fetched inventory spans multiple local pages", async () => {
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json(
          makePage(
            Array.from({ length: 11 }, (_, index) =>
              makeCert({
                id: index + 1,
                domain: `cert-${index + 1}.example.net`,
              }),
            ),
          ),
        ),
      ),
    );

    renderPage();
    await screen.findByText("cert-1.example.net");
    expect(
      screen.getByRole("button", { name: /Go to previous page/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Go to next page/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Page 1 of 2/i)).toBeInTheDocument();
  });

  it("filters empty state message when filters applied but no results", async () => {
    server.use(
      http.get(DISCOVERY_URL, () =>
        HttpResponse.json({
          content: [],
          totalElements: 0,
          totalPages: 0,
          number: 0,
          size: 100,
        }),
      ),
    );

    renderPage();

    await waitFor(() => {
      expect(
        screen.queryByText("No certificates match the current filters"),
      ).not.toBeInTheDocument();
    });
  });
  describe("unmanaged certificate hand-off", () => {
    const inDays = (days: number) =>
      new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    const deploymentCredential = {
      credentialXref: "cred-aws-001",
      provider: "AWS_ACM",
      type: "DEPLOYMENT",
      description: "AWS Test",
      status: "ACTIVE",
      secretHandle: "https://vault/secrets/aws",
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-02T00:00:00Z",
    };

    it("links a single expiring certificate straight to issuing it", async () => {
      server.use(
        http.get(CREDENTIALS_URL, () =>
          HttpResponse.json({ items: [deploymentCredential], totalItems: 1 }),
        ),
        http.get(DISCOVERY_URL, () =>
          HttpResponse.json(
            makePage([
              makeCert({
                id: 1,
                domain: "only.example.net",
                notAfter: inDays(10),
              }),
              makeCert({ id: 2, domain: "later.example.net" }),
            ]),
          ),
        ),
      );

      renderPage();

      const issue = await screen.findByRole("link", {
        name: "Issue with CertPing",
      });
      expect(issue).toHaveAttribute(
        "href",
        "/cert-manager/add?domain=only.example.net",
      );
      const callout = issue.closest('[role="alert"]') as HTMLElement;
      expect(callout).toHaveTextContent(
        "Reissue it through CertPing and it renews on its own. Add AWS Certificate Manager as a deployment target to redeploy automatically.",
      );
      expect(callout).not.toHaveTextContent(/renew and redeploy on their own/);
      expect(
        await screen.findByRole("button", { name: /Trigger scan/i }),
      ).toHaveClass("mg-btn-outline");
    });

    it("focuses the expiring set first when several certificates need reissuing", async () => {
      const user = userEvent.setup();
      const requested: string[] = [];
      server.use(
        http.get(DISCOVERY_URL, ({ request }) => {
          requested.push(new URL(request.url).searchParams.toString());
          return HttpResponse.json(
            makePage([
              makeCert({ id: 1, domain: "a.example.net", notAfter: inDays(5) }),
              makeCert({ id: 2, domain: "b.example.net", notAfter: inDays(9) }),
            ]),
          );
        }),
      );

      renderPage();

      const show = await screen.findByRole("button", {
        name: "Show expiring",
      });
      expect(show).toHaveClass("mg-btn-primary");
      expect(
        screen.queryByRole("link", { name: "Issue with CertPing" }),
      ).not.toBeInTheDocument();

      await user.click(show);

      await waitFor(() =>
        expect(
          requested.some(
            (query) =>
              query.includes("managed=false") &&
              query.includes("expiresWithinDays=30"),
          ),
        ).toBe(true),
      );
    });

    it("offers no issuing while certificate issuance is switched off", async () => {
      mockIssuanceEnabled = false;
      server.use(
        http.get(DISCOVERY_URL, () =>
          HttpResponse.json(
            makePage([
              makeCert({
                id: 1,
                domain: "only.example.net",
                notAfter: inDays(10),
              }),
            ]),
          ),
        ),
      );

      renderPage();

      expect(
        await screen.findByRole("button", { name: "Show it" }),
      ).toHaveClass("mg-btn-outline");
      expect(
        screen.queryByRole("link", { name: "Issue with CertPing" }),
      ).not.toBeInTheDocument();
    });
  });
});
