// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { OrganizationPanel } from "@/components/settings/organization-access/organization-panel";

const refetch = jest.fn();
const organizationsState: {
  data: unknown[] | undefined;
  error: unknown;
  isLoading: boolean;
} = { data: undefined, error: null, isLoading: false };

const pushMock = jest.fn();
const establishSessionMock = jest.fn();
let authUser: { id: number; organizationId: string | null } = {
  id: 1,
  organizationId: "1",
};

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: authUser,
    isSuperAdmin: true,
    isLoading: false,
    establishSession: establishSessionMock,
  }),
}));

jest.mock("@/lib/backend/organizations", () => ({
  setWorkingOrganization: jest.fn(),
  getOrganizationIdValue: (organization: { organizationId: string }) =>
    organization.organizationId,
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: () => true,
  useIsOrgFeatureEnabled: () => true,
}));

jest.mock("@/hooks/use-responsive-view-mode", () => ({
  useResponsiveViewMode: () => ["table", jest.fn()],
}));

jest.mock("@/lib/post-auth", () => ({
  getPostAuthRoute: () => "/dashboard",
}));

jest.mock("@/lib/authz", () => ({
  canManageOrganizations: () => true,
  canUpdateOrganizations: () => true,
  canViewOrganizations: () => true,
}));

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

jest.mock("@/hooks/organizations", () => {
  const mutation = () => ({ mutateAsync: jest.fn(), isPending: false });
  return {
    getApiErrorMessage: (error: unknown, fallback: string) =>
      error instanceof Error ? error.message : fallback,
    getOrganizationIdValue: (organization: { organizationId: string }) =>
      organization.organizationId,
    useOrganizations: () => ({ ...organizationsState, refetch }),
    useOrganizationById: () => ({
      data: undefined,
      error: null,
      isLoading: false,
      refetch: jest.fn(),
    }),
    useCreateOrganization: mutation,
    useUpdateOrganization: mutation,
    useDeleteOrganization: mutation,
  };
});

describe("OrganizationPanel", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    refetch.mockReset();
    organizationsState.data = undefined;
    organizationsState.error = null;
    authUser = { id: 1, organizationId: "1" };
  });

  it("tells a super admin without a working organization how to open one, and switches on request", async () => {
    authUser = { id: 1, organizationId: null };
    organizationsState.data = [
      {
        organizationId: "7",
        name: "Acme Ltd",
        slug: "acme",
        domain: "acme.example",
        active: true,
      },
    ];
    const { setWorkingOrganization } = jest.requireMock(
      "@/lib/backend/organizations",
    );
    setWorkingOrganization.mockResolvedValue({
      organizationId: 7,
      organizationName: "Acme Ltd",
      accessToken: "t",
      refreshToken: "r",
    });
    establishSessionMock.mockResolvedValue({ user: { organizationId: "7" } });
    render(<OrganizationPanel />);

    expect(screen.getByTestId("no-working-organization")).toHaveTextContent(
      /not working in an organization yet/i,
    );

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /acme ltd/i }));
    await user.click(
      await screen.findByRole("menuitem", {
        name: /work in this organization/i,
      }),
    );

    await waitFor(() =>
      expect(setWorkingOrganization).toHaveBeenCalledWith("7"),
    );
    expect(establishSessionMock).toHaveBeenCalledWith({
      organizationId: 7,
      organizationName: "Acme Ltd",
      accessToken: "t",
      refreshToken: "r",
    });
    expect(pushMock).toHaveBeenCalledWith("/dashboard");
  });

  it("marks the organization the super admin works in and offers no switch for it", () => {
    organizationsState.data = [
      {
        organizationId: "1",
        name: "Home Org",
        slug: "home",
        domain: "home.example",
        active: true,
      },
    ];
    render(<OrganizationPanel />);
    expect(screen.getByText("Working here")).toBeInTheDocument();
    expect(
      screen.queryByTestId("no-working-organization"),
    ).not.toBeInTheDocument();
  });

  it("says the organizations could not be loaded instead of showing an empty table", async () => {
    organizationsState.error = new Error("Organization service unavailable");
    render(<OrganizationPanel />);

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Organization service unavailable",
    );
    expect(
      screen.queryByText(/No organizations match/),
    ).not.toBeInTheDocument();
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Retry" }));
    expect(refetch).toHaveBeenCalled();
  });

  it("lists organizations with long domains kept on one line", () => {
    organizationsState.data = [
      {
        organizationId: "7",
        name: "Acme Ltd",
        slug: "acme",
        domain: "a-very-long-subdomain.of.acme-holdings.example",
        active: true,
      },
    ];
    render(<OrganizationPanel />);

    expect(
      screen.getByTitle("a-very-long-subdomain.of.acme-holdings.example"),
    ).toHaveClass("truncate");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
