// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import EntLoginForm from "./ent-login-form";

const replaceMock = jest.fn();
const loginUserMock = jest.fn();
const loginWithMfaMock = jest.fn();
const establishSessionMock = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
}));
jest.mock("@/lib/backend/auth", () => ({
  loginUser: (payload: unknown) => loginUserMock(payload),
  loginWithMfa: (payload: unknown) => loginWithMfaMock(payload),
}));
let ssoLogin: { label: string; startPath: string } | null = null;
let emailEnabled = true;
jest.mock("@/hooks/use-deployment-mode", () => ({
  useSsoLogin: () => ssoLogin,
  useEmailEnabled: () => emailEnabled,
}));
jest.mock("@/lib/api-base-url", () => ({
  apiBaseUrl: () => "https://certping.example.com",
}));
jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ establishSession: establishSessionMock, isLoading: false }),
}));
jest.mock("@/lib/post-auth", () => ({ getPostAuthRoute: () => "/overview" }));
jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));
jest.mock("@/components/auth/auth-card-shell", () => ({
  AuthCardShell: ({
    title,
    children,
    footer,
  }: {
    title: string;
    children: React.ReactNode;
    footer?: React.ReactNode;
  }) => (
    <section>
      <h1>{title}</h1>
      {children}
      <footer>{footer}</footer>
    </section>
  ),
}));

function renderForm() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <EntLoginForm signedOutReason={null} />
    </QueryClientProvider>,
  );
}

async function submitPassword() {
  fireEvent.change(screen.getByLabelText(/username or email/i), {
    target: { value: "ada" },
  });
  fireEvent.change(screen.getByLabelText(/^password$/i), {
    target: { value: "correct horse" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
  await waitFor(() =>
    expect(loginUserMock).toHaveBeenCalledWith({
      identifier: "ada",
      password: "correct horse",
    }),
  );
}

describe("EntLoginForm", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    ssoLogin = null;
    emailEnabled = true;
    establishSessionMock.mockResolvedValue({ user: { permissions: [] } });
  });

  it("offers a reset email only when the installation can send email", () => {
    const { unmount } = renderForm();
    expect(
      screen.getByRole("link", { name: "Reset it by email" }),
    ).toBeInTheDocument();
    unmount();

    emailEnabled = false;
    renderForm();
    expect(
      screen.queryByRole("link", { name: "Reset it by email" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/Ask an administrator to reset it/),
    ).toBeInTheDocument();
  });

  it("shows a single sign-on button only when the installation has a provider", () => {
    const { unmount } = renderForm();
    expect(
      screen.queryByRole("link", { name: /continue with/i }),
    ).not.toBeInTheDocument();
    unmount();

    ssoLogin = { label: "Okta", startPath: "/oauth2/authorization/sso" };
    renderForm();
    expect(
      screen.getByRole("link", { name: "Continue with Okta" }),
    ).toHaveAttribute(
      "href",
      "https://certping.example.com/oauth2/authorization/sso",
    );
  });

  it("signs in straight away when no second factor is set", async () => {
    loginUserMock.mockResolvedValue({
      token: "t",
      email: "ada@example.com",
      roles: [],
      permissions: [],
    });
    renderForm();
    await submitPassword();
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/overview"));
    expect(loginWithMfaMock).not.toHaveBeenCalled();
  });

  it("asks for a one-time code when the password step returns a challenge", async () => {
    loginUserMock.mockResolvedValue({
      mfaRequired: true,
      mfaToken: "challenge",
      email: "",
      roles: [],
      permissions: [],
    });
    loginWithMfaMock.mockResolvedValue({
      token: "t",
      email: "ada@example.com",
      roles: [],
      permissions: [],
    });
    renderForm();
    await submitPassword();

    expect(establishSessionMock).not.toHaveBeenCalled();
    expect(
      await screen.findByRole("heading", { name: /enter your one-time code/i }),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/one-time code/i), {
      target: { value: "123 456" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: /verify and sign in/i }),
    );

    await waitFor(() =>
      expect(loginWithMfaMock).toHaveBeenCalledWith({
        mfaToken: "challenge",
        code: "123 456",
      }),
    );
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/overview"));
  });

  it("goes back to the password step on request", async () => {
    loginUserMock.mockResolvedValue({
      mfaRequired: true,
      mfaToken: "challenge",
      email: "",
      roles: [],
      permissions: [],
    });
    renderForm();
    await submitPassword();
    await screen.findByRole("heading", { name: /enter your one-time code/i });
    fireEvent.click(screen.getByRole("button", { name: /back to sign in/i }));
    expect(
      await screen.findByRole("heading", { name: /sign in to certping/i }),
    ).toBeInTheDocument();
  });
});
