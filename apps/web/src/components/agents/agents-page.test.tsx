// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: { get: jest.fn(), post: jest.fn(), delete: jest.fn() },
  };
});

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuth(),
}));

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { AgentsPage } from "@/components/agents/agents-page";
import { apiClient, apiRoutes } from "@/lib/api";
import type { Agent } from "@/lib/backend/agents";

const mockAuth = jest.fn();

const client = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
  delete: jest.Mock;
};

const ADMIN = {
  user: {
    id: "u1",
    organizationId: "7",
    roles: ["ORGANIZATION_ADMIN"],
    permissions: [],
  },
  isSuperAdmin: false,
  isLoading: false,
};

const baseAgent: Agent = {
  agentId: 11,
  name: "datacenter-east",
  tokenPrefix: "cpa_abc123",
  tokenCreatedAt: "2026-09-01T00:00:00Z",
  tokenExpiresAt: null,
  revoked: false,
  status: "ONLINE",
  lastSeenAt: new Date(Date.now() - 2 * 60_000).toISOString(),
  version: "1.4.0",
  hostname: "edge-01.corp",
  os: "Linux 6.8",
  javaVersion: "21.0.4",
  secretStore: "AZURE_KV",
  maxConcurrentJobs: 8,
  proxyConfigured: true,
  bundled: false,
  acme: {
    directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory",
    environment: "STAGING",
    contactEmail: "pki@example.com",
  },
  globalsignConfigured: true,
  capabilities: {
    deploymentTargets: ["KUBERNETES_SECRETS", "AWS_ACM"],
    discoveryTargets: ["AZURE_KV"],
    dnsProviders: ["CERTPING", "CLOUDFLARE"],
  },
};

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <AgentsPage />
    </QueryClientProvider>,
  );
}

function serveAgents(agents: Agent[]) {
  client.get.mockImplementation((url: string) => {
    if (url === apiRoutes.query.agent.agents) {
      return Promise.resolve({ data: { agents } });
    }
    const match = agents.find(
      (agent) => url === apiRoutes.query.agent.agentById(agent.agentId),
    );
    if (match) return Promise.resolve({ data: match });
    if (url === apiRoutes.query.agent.health) {
      return Promise.resolve({
        data: {
          organizationId: 7,
          overallStatus: "HEALTHY",
          listening: true,
          checkedAt: new Date(Date.now() + 1000).toISOString(),
          stale: false,
          failureReason: null,
        },
      });
    }
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

describe("AgentsPage", () => {
  beforeEach(() => {
    mockAuth.mockReturnValue(ADMIN);
  });

  it("lists agents with a status pill for each state", async () => {
    serveAgents([
      { ...baseAgent, agentId: 1, name: "online-agent", bundled: true },
      {
        ...baseAgent,
        agentId: 2,
        name: "offline-agent",
        status: "OFFLINE",
        secretStore: "AWS_SECRETS_MANAGER",
      },
      {
        ...baseAgent,
        agentId: 3,
        name: "new-agent",
        status: "NEVER_SEEN",
        lastSeenAt: null,
        version: null,
        hostname: null,
        secretStore: null,
      },
      {
        ...baseAgent,
        agentId: 4,
        name: "old-agent",
        status: "OFFLINE",
        revoked: true,
        secretStore: "GCP_SECRET_MANAGER",
        tokenExpiresAt: "2026-01-01T00:00:00Z",
      },
      {
        ...baseAgent,
        agentId: 5,
        name: "local-agent",
        secretStore: "LOCAL",
        bundled: true,
      },
    ]);

    renderPage();

    const online = await screen.findByTestId("agent-row-1");
    expect(within(online).getByText("Online")).toBeInTheDocument();
    expect(within(online).getByText("Bundled")).toBeInTheDocument();
    expect(within(online).getByText("2 minutes ago")).toBeInTheDocument();
    expect(within(online).getByText("Azure Key Vault")).toBeInTheDocument();
    expect(within(online).getByText("1.4.0")).toBeInTheDocument();
    expect(within(online).getByText("edge-01.corp")).toBeInTheDocument();
    expect(within(online).getByText("Never")).toBeInTheDocument();

    const offline = screen.getByTestId("agent-row-2");
    expect(within(offline).getByText("Offline")).toBeInTheDocument();
    expect(
      within(offline).getByText("AWS Secrets Manager"),
    ).toBeInTheDocument();

    const never = screen.getByTestId("agent-row-3");
    expect(within(never).getByText("Never connected")).toBeInTheDocument();

    const revoked = screen.getByTestId("agent-row-4");
    expect(within(revoked).getByText("Revoked")).toBeInTheDocument();
    expect(within(revoked).queryByText("Offline")).not.toBeInTheDocument();
    expect(
      within(revoked).getByText("Google Secret Manager"),
    ).toBeInTheDocument();
    expect(within(revoked).getByText(/^Expired /)).toBeInTheDocument();

    expect(
      within(screen.getByTestId("agent-row-5")).getByText(
        "Local encrypted files",
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Add agent/ })).toBeVisible();
  });

  it("explains what an agent is when there are none and offers Add agent", async () => {
    serveAgents([]);

    renderPage();

    expect(await screen.findByText("No agents yet")).toBeInTheDocument();
    expect(
      screen.getByText(
        /An agent is a small program you run in your own network/,
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Add agent/ })).toHaveLength(
      1,
    );
  });

  it("shows the details with the environment variable for each setting and no secret", async () => {
    serveAgents([
      {
        ...baseAgent,
        token: "cpa_abc123LEAKEDVALUE",
        globalsignApiSecret: "LEAKEDVALUE",
      } as Agent,
    ]);
    const user = userEvent.setup();

    renderPage();

    await user.click(
      await screen.findByRole("button", { name: "datacenter-east" }),
    );
    const panel = await screen.findByRole("dialog");

    for (const heading of ["Connection", "Settings", "Can do"]) {
      expect(within(panel).getByText(heading)).toBeInTheDocument();
    }
    for (const env of [
      "AGENT_SECRET_STORE_PROVIDER",
      "CERTPING_AGENT_MAX_CONCURRENT_JOBS",
      "ACME_DIRECTORY_URL",
      "ACME_ACCOUNT_EMAIL",
      "HTTPS_PROXY",
      "AGENT_GLOBALSIGN_API_KEY",
    ]) {
      expect(within(panel).getByText(env)).toBeInTheDocument();
    }
    expect(within(panel).getAllByText("Set on the agent")[0]).toHaveAttribute(
      "href",
      "https://github.com/certping-labs/certping/blob/main/docs/configuration.md",
    );
    expect(
      within(panel).getByText("Staging (test certificates)"),
    ).toBeInTheDocument();
    expect(within(panel).getByText("pki@example.com")).toBeInTheDocument();
    expect(within(panel).getByText("Linux 6.8")).toBeInTheDocument();
    expect(within(panel).getByText("21.0.4")).toBeInTheDocument();
    expect(within(panel).getByText("Kubernetes Secrets")).toBeInTheDocument();
    // AWS ACM deployment, Azure Key Vault discovery and Cloudflare DNS have no end-to-end test yet.
    expect(within(panel).getAllByTestId("beta-badge")).toHaveLength(3);
    // Only the token prefix is shown, never a token or credential value.
    expect(panel.textContent).toContain("cpa_abc123...");
    // Even a field the page does not know about (a token value) is never rendered.
    expect(panel.textContent).not.toContain("LEAKEDVALUE");
    expect(within(panel).getByText("Set up")).toBeInTheDocument();
  });

  it("runs a health check and shows its result with the failing checks", async () => {
    serveAgents([baseAgent]);
    const serveAgentsGet = client.get.getMockImplementation()!;
    client.get.mockImplementation((url: string) => {
      if (url === apiRoutes.query.agent.deepCheck("dhc-1")) {
        return Promise.resolve({
          data: { deepCheckId: "dhc-1", status: "PARTIAL" },
        });
      }
      if (url === apiRoutes.query.agent.deepCheckMetrics("dhc-1")) {
        return Promise.resolve({
          data: [
            {
              metricKey: "a",
              metricName: "Agent Gateway Connection Configured",
              status: "PASS",
            },
            {
              metricKey: "b",
              metricName: "Secret Store Path Exists",
              status: "PASS",
              path: "local:one",
            },
            {
              metricKey: "c",
              metricName: "Secret Store Path Exists",
              status: "FAIL",
              path: "local:gone",
            },
          ],
        });
      }
      return serveAgentsGet(url);
    });
    client.post.mockResolvedValue({
      data: { deepCheckId: "dhc-1", requestedAt: new Date().toISOString() },
    });
    const user = userEvent.setup();

    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "datacenter-east" }),
    );
    await user.click(
      await screen.findByRole("button", { name: /Run health check/ }),
    );

    expect(client.post).toHaveBeenCalledWith(
      apiRoutes.mutation.agent.runHealthCheck(11),
    );
    expect(
      screen.getByText(
        "Health checks go to the organization's queue, so any of its agents may answer.",
      ),
    ).toBeInTheDocument();
    expect(await screen.findByText("Problems found")).toBeInTheDocument();
    expect(
      await screen.findByText("2 of 3 checks passed."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Secret Store Path Exists: local:gone"),
    ).toBeInTheDocument();
  });

  it("revokes the token after the same confirmation as the organization page", async () => {
    serveAgents([baseAgent]);
    client.delete.mockResolvedValue({});
    const user = userEvent.setup();

    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "datacenter-east" }),
    );
    await user.click(
      await screen.findByRole("button", { name: "Revoke token" }),
    );

    expect(
      await screen.findByText(
        'Revoke "datacenter-east"? The agent using it stops connecting.',
      ),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() =>
      expect(client.delete).toHaveBeenCalledWith(
        apiRoutes.query.agent.tokenById(11),
        { params: undefined },
      ),
    );
  });

  it("creates a token, shows it once with Docker and Kubernetes commands, and forgets it on close", async () => {
    serveAgents([]);
    client.post.mockResolvedValue({
      data: {
        token: {
          id: 12,
          organizationId: "7",
          name: "lab",
          tokenPrefix: "cpa_x",
        },
        value: "cpa_xNEWTOKEN",
        gatewayPath: "/api/v1/agent-gateway",
        dockerCommand:
          "docker run -d --name certping-agent \\\n  -e CERTPING_SERVER_URL=http://localhost \\\n  -e CERTPING_AGENT_TOKEN=cpa_xNEWTOKEN \\\n  -e AGENT_SECRET_STORE_PROVIDER=AZURE_KV \\\n  ghcr.io/certping-labs/certping-agent:2.3.1",
      },
    });
    const user = userEvent.setup();

    renderPage();
    await user.click(await screen.findByRole("button", { name: /Add agent/ }));
    const panel = await screen.findByRole("dialog");
    await user.type(within(panel).getByLabelText("Name"), "lab");
    await user.selectOptions(
      within(panel).getByLabelText("Token expires after"),
      "90",
    );
    await user.click(
      within(panel).getByRole("button", { name: "Create token" }),
    );

    expect(
      await within(panel).findByText(
        "Copy this token now. It is shown only once.",
      ),
    ).toBeInTheDocument();
    expect(client.post).toHaveBeenCalledWith(
      apiRoutes.query.agent.tokens,
      { name: "lab", serverUrl: window.location.origin, expiresInDays: 90 },
      { params: undefined },
    );
    expect(within(panel).getByText("cpa_xNEWTOKEN")).toBeInTheDocument();
    expect(panel.textContent).toContain(
      "ghcr.io/certping-labs/certping-agent:2.3.1",
    );
    expect(
      within(panel).getByText(
        "The agent connects to this server over outbound HTTPS. It accepts inbound connections only if you turn on SCEP for devices.",
      ),
    ).toBeInTheDocument();

    const docker = within(panel).getByText(/docker run -d/);
    // AWS Secrets Manager is the default; local files are only for the bundled agent.
    expect(docker.textContent).toContain(
      "-e AGENT_SECRET_STORE_PROVIDER=AWS_SECRETS_MANAGER",
    );
    expect(docker.textContent).not.toMatch(/LOCAL/);

    await user.click(within(panel).getByRole("tab", { name: "Kubernetes" }));
    expect(
      await within(panel).findByText(/helm install certping-agent/),
    ).toBeInTheDocument();

    await user.click(within(panel).getByRole("button", { name: "Done" }));
    await waitFor(() =>
      expect(screen.queryByText("cpa_xNEWTOKEN")).not.toBeInTheDocument(),
    );
    await user.click(screen.getByRole("button", { name: /Add agent/ }));
    expect(
      await screen.findByRole("button", { name: "Create token" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("cpa_xNEWTOKEN")).not.toBeInTheDocument();
  });

  it("builds identity-based Docker and Helm commands for a cloud secret store", async () => {
    serveAgents([]);
    client.post.mockResolvedValue({
      data: {
        token: {
          id: 13,
          organizationId: "7",
          name: "aws",
          tokenPrefix: "cpa_y",
        },
        value: "cpa_yNEWTOKEN",
        gatewayPath: "/api/v1/agent-gateway",
        dockerCommand: "docker run ghcr.io/certping-labs/certping-agent:2.3.1",
      },
    });
    const user = userEvent.setup();

    renderPage();
    await user.click(await screen.findByRole("button", { name: /Add agent/ }));
    const panel = await screen.findByRole("dialog");
    expect(
      within(panel).getByText("Where should this agent keep keys?"),
    ).toBeInTheDocument();
    expect(
      within(panel).queryByRole("radio", { name: /Local encrypted files/ }),
    ).not.toBeInTheDocument();
    expect(
      within(panel).getByRole("radio", { name: "AWS Secrets Manager" }),
    ).toBeChecked();
    expect(
      within(panel).getByText(
        "Remote agents keep keys in your cloud secret manager. Local encrypted files are used only by the agent bundled with the server.",
      ),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText(/No cloud secret is entered here/),
    ).toBeVisible();
    await user.click(
      within(panel).getByRole("button", { name: "Create token" }),
    );

    const docker = await within(panel).findByText(/docker run -d/);
    expect(docker.textContent).toContain(
      "-e AGENT_SECRET_STORE_PROVIDER=AWS_SECRETS_MANAGER",
    );
    expect(docker.textContent).toContain("-e AWS_REGION=<your-aws-region>");
    expect(docker.textContent).toContain("-e AWS_SM_AUTH_MODE=DEFAULT");
    expect(docker.textContent).toContain("IAM role");
    expect(docker.textContent).not.toMatch(
      /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|CERTPING_LOCAL_SECRET_KEY/,
    );

    await user.click(within(panel).getByRole("tab", { name: "Kubernetes" }));
    const helm = await within(panel).findByText(/helm install certping-agent/);
    expect(helm.textContent).toContain("./deploy/charts/certping-agent");
    expect(helm.textContent).toContain("--set image.tag=2.3.1");
    expect(helm.textContent).toContain(
      "--set tokenSecret.name=certping-agent-token",
    );
    expect(helm.textContent).toContain(
      "kubectl create secret generic certping-agent-token --from-literal=token=cpa_yNEWTOKEN",
    );
    expect(helm.textContent).toContain(
      "--set secretStore.provider=AWS_SECRETS_MANAGER",
    );
    expect(helm.textContent).toContain(
      "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn=arn:aws:iam::<account-id>:role/<role-name>",
    );
  });

  it("tells a member without the permission that the page is not for them", () => {
    mockAuth.mockReturnValue({
      ...ADMIN,
      user: { ...ADMIN.user, roles: ["VIEWER"], permissions: [] },
    });
    serveAgents([baseAgent]);

    renderPage();

    expect(
      screen.getByText("You do not have permission to manage agents."),
    ).toBeInTheDocument();
    expect(client.get).not.toHaveBeenCalled();
  });
});
