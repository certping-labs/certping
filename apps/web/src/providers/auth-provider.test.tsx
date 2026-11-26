// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";

import { AuthProvider } from "@/providers/auth-provider";
import AuthProviderDefault from "@/providers/auth-provider";

const replaceMock = jest.fn();
const useAuthMock = jest.fn();
const usePathnameMock = jest.fn();
const getActiveSubscriptionMock = jest.fn();
const pendingSignedOutReasonMock = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
  usePathname: () => usePathnameMock(),
}));

jest.mock("@/lib/session-end", () => ({
  ...jest.requireActual("@/lib/session-end"),
  getPendingSignedOutReason: () => pendingSignedOutReasonMock(),
}));

let mockFlagsReady = true;
jest.mock("@/hooks/use-feature-flags", () => ({
  useFeatureFlagsSync: () => undefined,
  useFeatureFlags: () => ({
    effectiveMap: {},
    status: mockFlagsReady ? "ready" : "pending",
    isReady: mockFlagsReady,
    isEnabled: () => mockFlagsReady,
  }),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => useAuthMock(),
}));

jest.mock("@/components/ui/loading-templates", () => ({
  FullScreenLoader: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="full-screen-loader">{children}</div>
  ),
}));

describe("AuthProvider route gating", () => {
  const originalLocation = window.location;
  const originalAppMode = process.env.NEXT_PUBLIC_APP_MODE;

  beforeEach(() => {
    replaceMock.mockReset();
    useAuthMock.mockReset();
    usePathnameMock.mockReset();
    getActiveSubscriptionMock.mockReset();
    getActiveSubscriptionMock.mockReturnValue(new Promise(() => undefined));
    pendingSignedOutReasonMock.mockReset();
    mockFlagsReady = true;
    process.env.NEXT_PUBLIC_APP_MODE = originalAppMode;
    window.history.replaceState(null, "", "/");
  });

  afterAll(() => {
    window.history.replaceState(null, "", originalLocation.href);
  });

  it("redirects unauthenticated users on private routes", () => {
    usePathnameMock.mockReturnValue("/dashboard");
    useAuthMock.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      isSuperAdmin: false,
    });

    render(
      <AuthProvider>
        <div>Protected Content</div>
      </AuthProvider>,
    );

    expect(replaceMock).toHaveBeenCalledWith("/login");
    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  it("keeps the sign-out reason when it redirects after a forced sign-out", () => {
    pendingSignedOutReasonMock.mockReturnValue("organization-suspended");
    usePathnameMock.mockReturnValue("/dashboard");
    useAuthMock.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      isSuperAdmin: false,
    });

    render(
      <AuthProvider>
        <div>Protected Content</div>
      </AuthProvider>,
    );

    expect(replaceMock).toHaveBeenCalledWith(
      "/login?signedOut=organization-suspended",
    );
  });

  it("redirects authenticated users away from login to their default route", async () => {
    usePathnameMock.mockReturnValue("/login");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: true,
      user: {
        id: "root-1",
        email: "root@example.com",
        organizationId: null,
        organizationName: null,
        roles: ["SUPER_ADMIN"],
        permissions: ["organization:view"],
        authMethod: "LOCAL",
      },
    });

    render(
      <AuthProvider>
        <div>Login Content</div>
      </AuthProvider>,
    );

    await waitFor(() =>
      expect(replaceMock).toHaveBeenCalledWith(
        "/settings/organization-access?tab=organization",
      ),
    );
  });

  it("waits for the flags before choosing where a signed-in user lands", async () => {
    mockFlagsReady = false;
    usePathnameMock.mockReturnValue("/login");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: false,
      user: {
        id: "u-1",
        email: "ops@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["notifications:view"],
        authMethod: "LOCAL",
      },
    });

    const { rerender } = render(
      <AuthProvider>
        <div>Login Content</div>
      </AuthProvider>,
    );
    expect(replaceMock).not.toHaveBeenCalled();

    mockFlagsReady = true;
    rerender(
      <AuthProvider>
        <div>Login Content</div>
      </AuthProvider>,
    );

    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/incidents"));
  });

  it("redirects users with required password changes to account security", () => {
    usePathnameMock.mockReturnValue("/dashboard");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: false,
      user: {
        id: "org-user-1",
        email: "org-user@example.com",
        organizationId: "organization-1",
        organizationName: "Acme",
        roles: ["ORGANIZATION_ADMIN"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
        mustChangePassword: true,
      },
    });

    render(
      <AuthProvider>
        <div>Dashboard Content</div>
      </AuthProvider>,
    );

    expect(replaceMock).toHaveBeenCalledWith(
      "/settings/organization-access?tab=account&changePassword=true",
    );
  });

  it("forces the first super admin, who has an organization, to change the password", () => {
    usePathnameMock.mockReturnValue("/dashboard");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: true,
      user: {
        id: "admin-1",
        email: "admin@certping.local",
        organizationId: "1",
        organizationName: "My organization",
        roles: ["SUPER_ADMIN", "ORGANIZATION_ADMIN"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
        mustChangePassword: true,
      },
    });

    render(
      <AuthProvider>
        <div>Dashboard Content</div>
      </AuthProvider>,
    );

    expect(replaceMock).toHaveBeenCalledWith(
      "/settings/organization-access?tab=account&changePassword=true",
    );
  });

  it("does not force super admins without an organization through required password changes", () => {
    usePathnameMock.mockReturnValue("/settings/organization-access");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: true,
      user: {
        id: "root-1",
        email: "root@example.com",
        organizationId: null,
        organizationName: null,
        roles: ["SUPER_ADMIN"],
        permissions: ["organization:view"],
        authMethod: "LOCAL",
        mustChangePassword: true,
      },
    });

    render(
      <AuthProvider>
        <div>Organizations Content</div>
      </AuthProvider>,
    );

    expect(replaceMock).not.toHaveBeenCalledWith(
      "/settings/organization-access?tab=account&changePassword=true",
    );
    expect(screen.getByText("Organizations Content")).toBeInTheDocument();
  });

  it.each([
    ["/cert-manager/rotation", ["certificate:read"], true],
    ["/cert-manager/rotation", ["notifications:view"], false],
    ["/cert-manager/deployments", ["deployments:view"], true],
    ["/cert-manager/deployments", ["certificate:read"], false],
    ["/integrations/dns", ["credential:read"], true],
    ["/integrations/dns", ["certificate:read"], false],
    ["/settings/audit-logs", ["audit:view"], true],
    ["/settings/audit-logs", ["certificate:read"], false],
    ["/settings/organization-access", ["certificate:read"], true],
    ["/support", ["certificate:read"], true],
  ])(
    "gates %s for permissions %j: allowed %s",
    (path, permissions, allowed) => {
      usePathnameMock.mockReturnValue(path);
      useAuthMock.mockReturnValue({
        isAuthenticated: true,
        isLoading: false,
        isSuperAdmin: false,
        user: {
          id: "org-user-1",
          email: "org-user@example.com",
          organizationId: "organization-1",
          organizationName: "Acme",
          roles: ["VIEWER"],
          permissions,
          authMethod: "LOCAL",
        },
      });

      render(
        <AuthProvider>
          <div>Gated page</div>
        </AuthProvider>,
      );

      if (allowed) {
        expect(replaceMock).not.toHaveBeenCalled();
        expect(screen.getByText("Gated page")).toBeInTheDocument();
      } else {
        expect(replaceMock).toHaveBeenCalled();
      }
    },
  );

  it("sends a signed-in user to the setup page nowhere: setup is a sign-in entry route", async () => {
    usePathnameMock.mockReturnValue("/setup");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: false,
      user: {
        id: "org-user-1",
        email: "org-user@example.com",
        organizationId: "organization-1",
        organizationName: "Acme",
        roles: ["VIEWER"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
      },
    });

    render(
      <AuthProvider>
        <div>Setup</div>
      </AuthProvider>,
    );

    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/dashboard"));
  });

  it("redirects authenticated users from denied route to default route", () => {
    usePathnameMock.mockReturnValue("/cert-manager/manage");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: false,
      user: {
        id: "org-user-1",
        email: "org-user@example.com",
        organizationId: "organization-1",
        organizationName: "Acme",
        roles: [],
        permissions: ["notifications:view"],
        authMethod: "SSO",
      },
    });

    render(
      <AuthProvider>
        <div>Cert Manager</div>
      </AuthProvider>,
    );

    expect(replaceMock).toHaveBeenCalledWith("/incidents");
  });

  it("keeps restored pages visible when auth is loading with a valid local session", () => {
    usePathnameMock.mockReturnValue("/settings/organization-access");
    useAuthMock.mockReturnValue({
      accessToken: "access-token",
      expiresAt: Date.now() + 60_000,
      isAuthenticated: true,
      isLoading: true,
      isSuperAdmin: false,
      user: {
        id: "org-admin-1",
        email: "admin@example.com",
        organizationId: "organization-1",
        organizationName: "Acme",
        roles: ["ORGANIZATION_ADMIN"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
      },
    });

    render(
      <AuthProvider>
        <div>Restored Settings Content</div>
      </AuthProvider>,
    );

    expect(screen.getByText("Restored Settings Content")).toBeInTheDocument();
    expect(screen.queryByTestId("full-screen-loader")).not.toBeInTheDocument();
  });

  it("renders public routes without redirect when user is unauthenticated", () => {
    usePathnameMock.mockReturnValue("/public-page");
    useAuthMock.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      isSuperAdmin: false,
    });

    render(
      <AuthProvider>
        <div>Public Content</div>
      </AuthProvider>,
    );

    expect(screen.getByText("Public Content")).toBeInTheDocument();
    expect(screen.queryByTestId("full-screen-loader")).not.toBeInTheDocument();
    expect(replaceMock).not.toHaveBeenCalled();
  });

  it("redirects authenticated users from root to their default route", async () => {
    usePathnameMock.mockReturnValue("/");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: false,
      user: {
        id: "org-user-1",
        email: "org-user@example.com",
        organizationId: "organization-1",
        organizationName: "Acme",
        roles: [],
        permissions: ["notifications:view"],
        authMethod: "SSO",
      },
    });

    render(
      <AuthProvider>
        <div>Root Content</div>
      </AuthProvider>,
    );

    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/incidents"));
  });

  it("does not redirect when denied route is already the default route", () => {
    usePathnameMock.mockReturnValue("/incidents");
    useAuthMock.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      isSuperAdmin: false,
      user: {
        id: "org-user-1",
        email: "org-user@example.com",
        organizationId: "organization-1",
        organizationName: "Acme",
        roles: [],
        permissions: ["notifications:view"],
        authMethod: "SSO",
      },
    });

    render(
      <AuthProvider>
        <div>Incidents Content</div>
      </AuthProvider>,
    );

    expect(replaceMock).not.toHaveBeenCalled();
    expect(screen.getByText("Incidents Content")).toBeInTheDocument();
  });

  it("default export renders and gates the same as named export", () => {
    usePathnameMock.mockReturnValue("/dashboard");
    useAuthMock.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      isSuperAdmin: false,
    });

    render(
      <AuthProviderDefault>
        <div>Protected Content</div>
      </AuthProviderDefault>,
    );

    expect(replaceMock).toHaveBeenCalledWith("/login");
  });

  it("applies route access rules across certificate, integration and settings routes", () => {
    const deniedPaths = [
      "/cert-manager/deployments",
      "/cert-manager/rotation",
      "/integrations/connections",
      "/settings/organizations",
      "/settings/audit-logs",
    ];

    for (const deniedPath of deniedPaths) {
      replaceMock.mockClear();
      usePathnameMock.mockReturnValue(deniedPath);
      useAuthMock.mockReturnValue({
        isAuthenticated: true,
        isLoading: false,
        isSuperAdmin: false,
        user: {
          id: "org-user-1",
          email: "org-user@example.com",
          organizationId: "organization-1",
          organizationName: "Acme",
          roles: [],
          permissions: ["notifications:view"],
          authMethod: "SSO",
        },
      });

      const { unmount } = render(
        <AuthProvider>
          <div>Denied Content</div>
        </AuthProvider>,
      );

      expect(replaceMock).toHaveBeenCalledWith("/incidents");
      unmount();
    }
  });

  it("lets a super admin without an organization open the platform pages and not the organization ones", () => {
    const superAdminUser = {
      id: "root-1",
      email: "root@example.com",
      organizationId: null,
      organizationName: null,
      roles: ["SUPER_ADMIN"],
      permissions: ["organization:view", "audit:view"],
      authMethod: "LOCAL" as const,
    };
    const cases: Array<{ path: string; redirected: boolean }> = [
      { path: "/settings/organizations", redirected: false },
      { path: "/settings/organization-access", redirected: false },
      { path: "/support", redirected: false },
      // Needs an organization context.
      { path: "/dashboard", redirected: true },
      { path: "/cert-manager", redirected: true },
    ];

    for (const { path, redirected } of cases) {
      replaceMock.mockClear();
      usePathnameMock.mockReturnValue(path);
      useAuthMock.mockReturnValue({
        isAuthenticated: true,
        isLoading: false,
        isSuperAdmin: true,
        user: superAdminUser,
      });

      const { unmount } = render(
        <AuthProvider>
          <div>Platform Content</div>
        </AuthProvider>,
      );

      if (redirected) {
        expect(replaceMock).toHaveBeenCalledWith(
          "/settings/organization-access?tab=organization",
        );
      } else {
        expect(replaceMock).not.toHaveBeenCalled();
      }
      unmount();
    }
  });
});
