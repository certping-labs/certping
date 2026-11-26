// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { AccountPanel } from "@/components/settings/organization-access/account-panel";
import { changePassword, getCurrentUser } from "@/lib/backend/auth";
import { useAuth } from "@/hooks/use-auth";

const replaceMock = jest.fn();
let searchParams = new URLSearchParams();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
  useSearchParams: () => searchParams,
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: jest.fn(),
}));

jest.mock("@/lib/backend/auth", () => ({
  changePassword: jest.fn(),
  getCurrentUser: jest.fn(),
  getMfaStatus: jest.fn(() =>
    Promise.resolve({
      enabled: false,
      confirmedAt: null,
      recoveryCodesRemaining: 0,
    }),
  ),
  startMfaEnrollment: jest.fn(),
  confirmMfaEnrollment: jest.fn(),
  disableMfa: jest.fn(),
}));

jest.mock("sonner", () => ({
  toast: {
    dismiss: jest.fn(),
    error: jest.fn(),
    success: jest.fn(),
  },
}));

const mockedUseAuth = useAuth as jest.Mock;
const mockedChangePassword = changePassword as jest.Mock;
const mockedGetCurrentUser = getCurrentUser as jest.Mock;

describe("AccountPanel password change prompt", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    searchParams = new URLSearchParams("changePassword=true");
  });

  it("does not mandate password changes for super admins from the query param", async () => {
    mockedUseAuth.mockReturnValue({
      accessToken: "access-token",
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
    mockedGetCurrentUser.mockResolvedValue({
      email: "root@example.com",
      organizationName: null,
      roles: ["SUPER_ADMIN"],
      mustChangePassword: true,
    });

    renderAccountPage();

    await waitFor(() => {
      expect(screen.getByText("root@example.com")).toBeInTheDocument();
    });
    expect(screen.getByText("Change password")).toBeInTheDocument();
    expect(
      screen.queryByText("Please update your password before continuing."),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
  });

  it("opens the required password form for non-super-admin users", async () => {
    mockedUseAuth.mockReturnValue({
      accessToken: "access-token",
      isLoading: false,
      isSuperAdmin: false,
      user: {
        id: "org-user-1",
        email: "user@example.com",
        organizationId: "organization-1",
        organizationName: "Acme",
        roles: ["USER"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
        mustChangePassword: false,
      },
    });
    mockedGetCurrentUser.mockResolvedValue({
      email: "user@example.com",
      organizationName: "Acme",
      roles: ["USER"],
      mustChangePassword: false,
    });

    renderAccountPage();

    await waitFor(() => {
      expect(screen.getByLabelText("Current password")).toBeInTheDocument();
    });
    expect(
      screen.getByText("Please update your password before continuing."),
    ).toBeInTheDocument();
  });

  it("keeps an inline success message visible after password update succeeds", async () => {
    const user = userEvent.setup();
    searchParams = new URLSearchParams();
    mockedUseAuth.mockReturnValue({
      accessToken: "access-token",
      isLoading: false,
      isSuperAdmin: false,
      user: {
        id: "org-user-1",
        email: "user@example.com",
        organizationId: "organization-1",
        organizationName: "Acme",
        roles: ["USER"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
        mustChangePassword: false,
      },
    });
    mockedGetCurrentUser.mockResolvedValue({
      email: "user@example.com",
      organizationName: "Acme",
      roles: ["USER"],
      mustChangePassword: false,
    });
    mockedChangePassword.mockResolvedValue(undefined);

    renderAccountPage();

    await user.click(await screen.findByText("Change password"));
    const current = screen.getByLabelText("Current password");
    expect(current).toHaveAttribute("type", "password");
    await user.click(
      screen.getByRole("button", { name: "Show current password" }),
    );
    expect(current).toHaveAttribute("type", "text");
    expect(screen.getByLabelText("New password")).toHaveAttribute(
      "type",
      "password",
    );
    await user.type(current, "OldPassword1!");
    await user.type(screen.getByLabelText("New password"), "NewPassword1!");
    await user.type(
      screen.getByLabelText("Confirm new password"),
      "NewPassword1!",
    );
    await user.click(screen.getByRole("button", { name: "Update password" }));

    await waitFor(() => {
      expect(mockedChangePassword).toHaveBeenCalledWith({
        currentPassword: "OldPassword1!",
        newPassword: "NewPassword1!",
        confirmPassword: "NewPassword1!",
      });
    });
    expect(await screen.findByText("Password changed")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Password updated successfully. Use your new password the next time you sign in.",
      ),
    ).toBeInTheDocument();
  });
});

function renderAccountPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <AccountPanel />
    </QueryClientProvider>,
  );
}
