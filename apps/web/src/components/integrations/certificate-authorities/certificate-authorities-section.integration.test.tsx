// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import { CertificateAuthoritiesSection } from "@/components/integrations/certificate-authorities/certificate-authorities-section";
import { CA_KEY_IN_USE_MESSAGE } from "@/hooks/ca-credentials";
import { useAuthStore } from "@/stores/auth-store";
import { server } from "@/test/msw/server";

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

const ALL_PERMISSIONS = [
  "credential:read",
  "credential:create",
  "credential:rotate",
  "credential:delete",
];

let mockPermissions = ALL_PERMISSIONS;

const userWith = (permissions: string[]) => ({
  id: "user-1",
  email: "user@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions,
  authMethod: "LOCAL" as const,
});

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: userWith(mockPermissions),
    isSuperAdmin: false,
    isLoading: false,
  }),
}));

const API = process.env.NEXT_PUBLIC_API_URL as string;

// Secret-looking values the server must never send. They are planted in the
// payload to prove the page would not render them even if it did.
const LEAKED_SECRETS = ["dc-live-SECRET-123", "-----BEGIN PRIVATE KEY-----"];

const PAYLOAD = {
  authorities: [
    {
      id: "LETS_ENCRYPT",
      name: "Let's Encrypt",
      kind: "ACME",
      status: "CONFIGURED",
      configuredWhere: "AGENT",
      maturity: "TESTED",
      agents: [
        {
          agentId: "agent-a",
          agentName: "edge-agent",
          lastSeenAt: "2026-10-29T10:00:00Z",
          configured: true,
          acme: {
            directoryUrl: "https://acme-v02.api.letsencrypt.org/directory",
            environment: "PRODUCTION",
            contactEmail: "ops@example.com",
            accountUrl: "https://acme-v02.api.letsencrypt.org/acme/acct/42",
            keyType: "EC P-256",
            createdAt: "2026-01-15T00:00:00Z",
            privateKey: LEAKED_SECRETS[1],
          },
        },
        {
          agentId: "agent-b",
          agentName: "lab-agent",
          lastSeenAt: null,
          configured: true,
          acme: {
            directoryUrl:
              "https://acme-staging-v02.api.letsencrypt.org/directory",
            environment: "STAGING",
            contactEmail: "",
            accountUrl: null,
            keyType: null,
            createdAt: null,
          },
        },
      ],
      credentials: [],
      docsPath: "docs/integrations.md#certificate-authorities",
    },
    {
      id: "DIGICERT",
      name: "DigiCert",
      kind: "API",
      status: "CONFIGURED",
      configuredWhere: "ORGANIZATION",
      maturity: "BETA",
      agents: [],
      credentials: [
        {
          credentialXref: "ca-1",
          description: "Production account",
          createdAt: "2026-03-01T00:00:00Z",
          updatedAt: "2026-04-01T00:00:00Z",
          apiKey: LEAKED_SECRETS[0],
        },
      ],
      docsPath: "docs/integrations.md#certificate-authorities",
    },
    {
      id: "GLOBALSIGN",
      name: "GlobalSign",
      kind: "API",
      status: "UNKNOWN",
      configuredWhere: "AGENT",
      maturity: "BETA",
      agents: [],
      credentials: [],
      docsPath: "docs/integrations.md#certificate-authorities",
    },
  ],
};

function renderSection() {
  useAuthStore.setState({
    user: userWith(mockPermissions),
    isLoading: false,
    isSuperAdmin: false,
    expiresAt: Date.now() + 60_000,
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <CertificateAuthoritiesSection />
    </QueryClientProvider>,
  );
}

const card = async (id: string) => screen.findByTestId(`ca-card-${id}`);

describe("Certificate authorities section", () => {
  beforeEach(() => {
    mockPermissions = ALL_PERMISSIONS;
    server.use(
      http.get(`${API}/api/v1/certificate-authorities`, () =>
        HttpResponse.json(PAYLOAD),
      ),
    );
  });

  it("shows one card per CA with its status and where it is set", async () => {
    renderSection();

    const letsEncrypt = await card("LETS_ENCRYPT");
    expect(within(letsEncrypt).getByText("Configured")).toBeInTheDocument();
    expect(within(letsEncrypt).getByText("Set on agent")).toBeInTheDocument();

    const digicert = await card("DIGICERT");
    expect(within(digicert).getByText("Configured")).toBeInTheDocument();
    expect(
      within(digicert).getByText("Saved in this organization"),
    ).toBeInTheDocument();

    const globalsign = await card("GLOBALSIGN");
    expect(
      within(globalsign).getByText("Waiting for an agent report"),
    ).toBeInTheDocument();
  });

  it("marks only the untested CAs as Beta", async () => {
    renderSection();

    expect(
      within(await card("LETS_ENCRYPT")).queryByTestId("beta-badge"),
    ).not.toBeInTheDocument();
    for (const id of ["DIGICERT", "GLOBALSIGN"]) {
      expect(
        within(await card(id)).getByTestId("beta-badge"),
      ).toBeInTheDocument();
    }
  });

  it("shows the ACME account each agent reports", async () => {
    renderSection();
    const letsEncrypt = await card("LETS_ENCRYPT");

    expect(
      within(letsEncrypt).getByText(
        "https://acme-v02.api.letsencrypt.org/directory",
      ),
    ).toBeInTheDocument();
    expect(within(letsEncrypt).getByText("Production")).toBeInTheDocument();
    expect(within(letsEncrypt).getByText("Staging")).toBeInTheDocument();
    expect(
      within(letsEncrypt).getByText("ops@example.com"),
    ).toBeInTheDocument();
    expect(within(letsEncrypt).getByText("EC P-256")).toBeInTheDocument();
    expect(
      within(letsEncrypt).getByText("Key kept by agent edge-agent"),
    ).toBeInTheDocument();
    expect(
      within(letsEncrypt).getByText(
        "No email set: set ACME_ACCOUNT_EMAIL on the agent",
      ),
    ).toBeInTheDocument();
    expect(
      within(letsEncrypt).getByText(
        "No account yet: created on the first certificate order",
      ),
    ).toBeInTheDocument();
    expect(
      within(letsEncrypt).getByText(
        "The account key stays in the agent's secret store. CertPing never shows it.",
      ),
    ).toBeInTheDocument();
    expect(
      within(letsEncrypt).getByRole("link", { name: "How to change" }),
    ).toHaveAttribute(
      "href",
      "https://github.com/certping-labs/certping/blob/main/docs/integrations.md#certificate-authorities",
    );
  });

  it("never shows key material or prefills a key field", async () => {
    const user = userEvent.setup();
    renderSection();
    await card("DIGICERT");

    const assertNoSecrets = () => {
      for (const secret of LEAKED_SECRETS) {
        expect(document.body.textContent).not.toContain(secret);
      }
      for (const input of Array.from(document.querySelectorAll("input"))) {
        expect(input.value).toBe("");
        expect(LEAKED_SECRETS).not.toContain(input.getAttribute("value"));
      }
    };

    assertNoSecrets();
    expect(document.querySelectorAll("input")).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Add key" }));
    const addDialog = await screen.findByRole("dialog");
    expect(within(addDialog).getByLabelText("API key")).toHaveAttribute(
      "type",
      "password",
    );
    assertNoSecrets();
    await user.click(within(addDialog).getByRole("button", { name: "Cancel" }));

    await user.click(
      screen.getByRole("button", { name: "Replace key Production account" }),
    );
    const replaceDialog = await screen.findByRole("dialog");
    expect(within(replaceDialog).getByLabelText("New API key")).toHaveAttribute(
      "type",
      "password",
    );
    assertNoSecrets();
  });

  it("adds a DigiCert key", async () => {
    const user = userEvent.setup();
    let body: unknown;
    server.use(
      http.post(`${API}/api/v1/credentials/ca`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({
          credentialXref: "ca-2",
          provider: "DIGICERT",
          description: "Second account",
          status: "ACTIVE",
        });
      }),
    );
    renderSection();
    await card("DIGICERT");

    await user.click(screen.getByRole("button", { name: "Add key" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "Second account");
    await user.type(within(dialog).getByLabelText("API key"), "dc-new-key");
    await user.click(within(dialog).getByRole("button", { name: "Save key" }));

    await waitFor(() =>
      expect(body).toEqual({
        provider: "DIGICERT",
        description: "Second account",
        credJson: { apiKey: "dc-new-key" },
      }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("replaces a DigiCert key without showing the old one", async () => {
    const user = userEvent.setup();
    let body: unknown;
    server.use(
      http.put(`${API}/api/v1/credentials/ca/ca-1`, async ({ request }) => {
        body = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderSection();
    await card("DIGICERT");

    await user.click(
      screen.getByRole("button", { name: "Replace key Production account" }),
    );
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("New API key"), "dc-rotated");
    await user.click(
      within(dialog).getByRole("button", { name: "Replace key" }),
    );

    await waitFor(() =>
      expect(body).toEqual({ credJson: { apiKey: "dc-rotated" } }),
    );
  });

  it("deletes a DigiCert key", async () => {
    const user = userEvent.setup();
    let deleted = false;
    server.use(
      http.delete(`${API}/api/v1/credentials/ca/ca-1`, () => {
        deleted = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderSection();
    await card("DIGICERT");

    await user.click(
      screen.getByRole("button", { name: "Delete key Production account" }),
    );
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: "Delete key" }),
    );

    await waitFor(() => expect(deleted).toBe(true));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("explains why a key in use cannot be deleted", async () => {
    const user = userEvent.setup();
    server.use(
      http.delete(`${API}/api/v1/credentials/ca/ca-1`, () =>
        HttpResponse.json(
          { message: "Credential is referenced" },
          { status: 409 },
        ),
      ),
    );
    renderSection();
    await card("DIGICERT");

    await user.click(
      screen.getByRole("button", { name: "Delete key Production account" }),
    );
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", { name: "Delete key" }),
    );

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      CA_KEY_IN_USE_MESSAGE,
    );
  });

  it("hides key actions from a read-only role", async () => {
    mockPermissions = ["credential:read"];
    renderSection();
    const digicert = await card("DIGICERT");

    expect(
      within(digicert).getByText("Production account"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Add key" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Replace key/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Delete key/ }),
    ).not.toBeInTheDocument();
  });
});
