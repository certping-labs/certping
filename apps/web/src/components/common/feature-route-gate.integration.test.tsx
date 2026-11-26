// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  QueryClient,
  QueryClientProvider,
  useQuery,
} from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import { FeatureRouteGate } from "@/components/common/feature-route-gate";
import {
  useFeatureFlagsSync,
  useIsRouteAvailable,
} from "@/hooks/use-feature-flags";
import { apiClient } from "@/lib/api";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { server } from "@/test/msw/server";
import type { SsoUser } from "@/types/auth";

// Exercise the real flag hooks: the shared setup stubs them as all-enabled.
jest.unmock("@/hooks/use-feature-flags");

let mockPathname = "/cert-manager/discovery";
jest.mock("next/navigation", () => ({
  usePathname: () => mockPathname,
}));

const mockUseAuth = jest.fn();
jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockUseAuth(),
}));

const API = process.env.NEXT_PUBLIC_API_URL as string;
const FLAGS_URL = `${API}/api/v1/feature-flags/effective`;
// The settings page's list: gates must never depend on it.
const MANAGEABLE_FLAGS_URL = `${API}/api/v1/feature-flags`;
const SCANS_URL = `${API}/api/v1/discovery/scans`;

const baseUser = {
  id: "u1",
  email: "user@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions: [] as string[],
  authMethod: "LOCAL",
};

function signIn(permissions: string[] = [], isSuperAdmin = false) {
  const user = { ...baseUser, permissions } as unknown as SsoUser;
  useAuthStore.setState({ user, isSuperAdmin });
  mockUseAuth.mockReturnValue({ isAuthenticated: true, user, isSuperAdmin });
}

function deferredFlags() {
  let release: (map: Record<string, boolean>) => void = () => undefined;
  const answer = new Promise<Record<string, boolean>>((resolve) => {
    release = resolve;
  });
  server.use(
    http.get(FLAGS_URL, async () =>
      HttpResponse.json({ effectiveMap: await answer }),
    ),
  );
  return (map: Record<string, boolean>) => release(map);
}

function answerFlags(map: Record<string, boolean>) {
  server.use(
    http.get(FLAGS_URL, () => HttpResponse.json({ effectiveMap: map })),
  );
}

let scanRequests = 0;

function DiscoveryPage() {
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: async () => (await apiClient.get(SCANS_URL)).data,
  });
  return <div>Discovery content {scans.isSuccess ? "loaded" : ""}</div>;
}

function FlagSync() {
  useFeatureFlagsSync();
  return null;
}

/** What navigation would do with these links, by the gate's own rule. */
function NavProbe({ hrefs }: { hrefs: string[] }) {
  const isRouteAvailable = useIsRouteAvailable();
  return (
    <ul aria-label="Navigation">
      {hrefs.filter(isRouteAvailable).map((href) => (
        <li key={href}>{href}</li>
      ))}
    </ul>
  );
}

function renderApp(
  page: React.ReactNode = <DiscoveryPage />,
  navHrefs: string[] = [],
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <FlagSync />
      <NavProbe hrefs={navHrefs} />
      <FeatureRouteGate>{page}</FeatureRouteGate>
    </QueryClientProvider>,
  );
}

describe("FeatureRouteGate (integration)", () => {
  beforeEach(() => {
    mockPathname = "/cert-manager/discovery";
    scanRequests = 0;
    useFeatureFlagStore.getState().reset();
    server.use(
      http.get(SCANS_URL, () => {
        scanRequests += 1;
        return HttpResponse.json([]);
      }),
      // A member without the settings permission: refused, as in production.
      http.get(MANAGEABLE_FLAGS_URL, () =>
        HttpResponse.json({}, { status: 403 }),
      ),
    );
  });

  afterEach(() => {
    server.resetHandlers();
    useAuthStore.setState({ user: null, isSuperAdmin: false });
  });

  it("shows a skeleton and fires nothing until flags load, then the page", async () => {
    signIn();
    const releaseFlags = deferredFlags();
    renderApp();

    expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
    expect(screen.queryByText(/Discovery content/)).not.toBeInTheDocument();
    expect(screen.queryByText(/isn't available/)).not.toBeInTheDocument();

    releaseFlags({ DISCOVERY: true });

    expect(
      await screen.findByText("Discovery content loaded"),
    ).toBeInTheDocument();
    expect(scanRequests).toBe(1);
  });

  it("shows the disabled page and never requests data when the flag is off", async () => {
    signIn(["audit:view"]);
    answerFlags({ DISCOVERY: false });
    renderApp();

    expect(
      await screen.findByRole("heading", {
        name: "Certificate discovery isn't available",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/ask your CertPing administrator/),
    ).toBeInTheDocument();
    expect(scanRequests).toBe(0);
  });

  it("treats a key the backend does not send as off", async () => {
    signIn();
    answerFlags({});
    renderApp();

    expect(
      await screen.findByText(/ask your CertPing administrator/),
    ).toBeInTheDocument();
  });

  it("names the first blocking flag of an all-of rule", async () => {
    signIn();
    mockPathname = "/integrations/deployment-targets";
    answerFlags({
      CREDENTIALS_MANAGEMENT: true,
      CERTIFICATE_DEPLOYMENT: false,
    });
    renderApp(<div>Targets</div>);

    expect(
      await screen.findByRole("heading", {
        name: "Certificate deployment isn't available",
      }),
    ).toBeInTheDocument();
  });

  it("shows a retryable error when the first flag fetch fails", async () => {
    signIn();
    server.use(
      http.get(FLAGS_URL, () => HttpResponse.json({}, { status: 500 }), {
        once: true,
      }),
    );
    renderApp();

    expect(
      await screen.findByRole("heading", { name: "This page couldn't load" }),
    ).toBeInTheDocument();
    expect(scanRequests).toBe(0);

    answerFlags({ DISCOVERY: true });
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(
      await screen.findByText("Discovery content loaded"),
    ).toBeInTheDocument();
  });

  it("renders ungated routes at once, even while flags are pending", () => {
    signIn();
    deferredFlags();
    mockPathname = "/incidents/system-notifications";
    renderApp(<div>Notifications</div>);

    expect(screen.getByText("Notifications")).toBeInTheDocument();
  });

  it("gates from /effective while the settings list answers 403", async () => {
    signIn();
    answerFlags({ DISCOVERY: true, PQC_READINESS: false });
    renderApp(<DiscoveryPage />, [
      "/cert-manager/discovery",
      "/cert-manager/cryptography",
    ]);

    expect(
      await screen.findByText("Discovery content loaded"),
    ).toBeInTheDocument();
    const nav = screen.getByRole("list", { name: "Navigation" });
    expect(nav).toHaveTextContent("/cert-manager/discovery");
    expect(nav).not.toHaveTextContent("/cert-manager/cryptography");
  });

  describe("a super admin signed in without an organization", () => {
    let discoveryRequests = 0;

    function signInWithoutOrganization() {
      const user = { ...baseUser, organizationId: null } as unknown as SsoUser;
      useAuthStore.setState({ user, isSuperAdmin: true });
      mockUseAuth.mockReturnValue({
        isAuthenticated: true,
        user,
        isSuperAdmin: true,
      });
    }

    beforeEach(() => {
      discoveryRequests = 0;
      server.use(
        http.get(`${API}/api/v1/discovery/certs`, () => {
          discoveryRequests += 1;
          return HttpResponse.json([]);
        }),
      );
    });

    function OrgDiscoveryPage() {
      useQuery({
        queryKey: ["discovery-no-org"],
        queryFn: async () =>
          (await apiClient.get(`${API}/api/v1/discovery/certs`)).data,
      });
      return <div>Discovery content</div>;
    }

    it("explains /cert-manager/discovery instead of fetching, and nav agrees", async () => {
      signInWithoutOrganization();
      mockPathname = "/cert-manager/discovery";
      renderApp(<OrgDiscoveryPage />, ["/cert-manager/discovery"]);

      expect(
        await screen.findByRole("heading", {
          name: "Certificate discovery works inside an organization",
        }),
      ).toBeInTheDocument();
      expect(
        screen.getByText("Sign in to an organization to use it."),
      ).toBeInTheDocument();
      expect(screen.queryByText("Discovery content")).not.toBeInTheDocument();
      expect(
        screen.getByRole("list", { name: "Navigation" }),
      ).toBeEmptyDOMElement();
      expect(discoveryRequests).toBe(0);
    });

    it("still shows audit logs, which serve platform-wide data", async () => {
      signInWithoutOrganization();
      mockPathname = "/settings/audit-logs";
      renderApp(<div>Audit logs content</div>, ["/settings/audit-logs"]);

      expect(await screen.findByText("Audit logs content")).toBeInTheDocument();
      expect(
        screen.getByRole("list", { name: "Navigation" }),
      ).toHaveTextContent("/settings/audit-logs");
    });
  });

  it("renders its states as labelled sections, never a second main", async () => {
    signIn();
    answerFlags({ DISCOVERY: false });
    const { container } = renderApp();

    const heading = await screen.findByRole("heading", {
      name: "Certificate discovery isn't available",
    });
    expect(heading.closest("section")).toHaveAttribute(
      "aria-labelledby",
      heading.id,
    );
    expect(container.querySelector("main")).toBeNull();
  });

  it("renders the flag error as a labelled section too", async () => {
    signIn();
    server.use(
      http.get(FLAGS_URL, () => HttpResponse.json({}, { status: 500 })),
    );
    const { container } = renderApp();

    const heading = await screen.findByRole("heading", {
      name: "This page couldn't load",
    });
    expect(heading.closest("section")).toHaveAttribute(
      "aria-labelledby",
      heading.id,
    );
    expect(container.querySelector("main")).toBeNull();
  });

  it("closes the page when a poll turns the flag off", async () => {
    signIn();
    answerFlags({ DISCOVERY: true });
    renderApp();
    await screen.findByText("Discovery content loaded");

    useFeatureFlagStore.getState().setEffectiveMap({ DISCOVERY: false });

    await waitFor(() =>
      expect(screen.queryByText(/Discovery content/)).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole("heading", {
        name: "Certificate discovery isn't available",
      }),
    ).toBeInTheDocument();
  });
});
