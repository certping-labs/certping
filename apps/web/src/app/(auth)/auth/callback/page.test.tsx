// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";

import CallbackPage from "./page";

const replaceMock = jest.fn();
const pushMock = jest.fn();
const establishSessionMock = jest.fn();
const exchangeSsoCodeMock = jest.fn();
const toastSuccessMock = jest.fn();
let params = new URLSearchParams();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock, push: pushMock }),
  useSearchParams: () => params,
}));
jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ establishSession: establishSessionMock }),
}));
jest.mock("@/lib/backend/auth", () => ({
  exchangeSsoCode: (code: string) => exchangeSsoCodeMock(code),
}));
jest.mock("sonner", () => ({
  toast: { success: (text: string) => toastSuccessMock(text) },
}));
jest.mock("@/lib/post-auth", () => ({ getPostAuthRoute: () => "/overview" }));
jest.mock("@/components/auth/auth-card-shell", () => ({
  AuthCardShell: ({
    title,
    children,
  }: {
    title: string;
    children: React.ReactNode;
  }) => (
    <section>
      <h1>{title}</h1>
      {children}
    </section>
  ),
}));

const visit = (query: string) => {
  window.history.replaceState(
    null,
    "",
    `/auth/callback${query ? `?${query}` : ""}`,
  );
  params = new URLSearchParams(query);
};

describe("SSO callback page", () => {
  const authResponse = {
    accessToken: "acc",
    refreshToken: "ref",
    expiresIn: 900,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    exchangeSsoCodeMock.mockResolvedValue(authResponse);
    establishSessionMock.mockResolvedValue({ user: { permissions: [] } });
  });

  it("trades the one-time code for a session once and opens the workspace", async () => {
    visit("code=one-time-123");
    render(<CallbackPage />);

    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/overview"));
    expect(exchangeSsoCodeMock).toHaveBeenCalledTimes(1);
    expect(exchangeSsoCodeMock).toHaveBeenCalledWith("one-time-123");
    expect(establishSessionMock).toHaveBeenCalledTimes(1);
    expect(establishSessionMock).toHaveBeenCalledWith(authResponse);
    expect(toastSuccessMock).toHaveBeenCalledWith("Signed in successfully.");
  });

  it("removes the code from the address bar before the exchange answers", () => {
    exchangeSsoCodeMock.mockReturnValue(new Promise(() => undefined));
    visit("code=one-time-123");
    render(<CallbackPage />);

    expect(window.location.search).toBe("");
    expect(window.location.pathname).toBe("/auth/callback");
    expect(
      screen.getByRole("heading", { name: /signing you in/i }),
    ).toBeInTheDocument();
  });

  it("never writes the code to the console", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map(
      (level) => jest.spyOn(console, level).mockImplementation(() => undefined),
    );
    exchangeSsoCodeMock.mockRejectedValue(new Error("expired"));
    visit("code=secret-code-xyz");
    render(<CallbackPage />);

    await screen.findByRole("heading", { name: /sign-in failed/i });
    for (const spy of spies) {
      expect(JSON.stringify(spy.mock.calls)).not.toContain("secret-code-xyz");
    }
  });

  it("shows the reason when the exchange is refused", async () => {
    exchangeSsoCodeMock.mockRejectedValue(new Error("Code expired."));
    visit("code=old");
    render(<CallbackPage />);

    expect(
      await screen.findByRole("heading", { name: /sign-in failed/i }),
    ).toBeInTheDocument();
    expect(establishSessionMock).not.toHaveBeenCalled();
    expect(replaceMock).not.toHaveBeenCalled();
  });

  it("explains a refusal in plain words and keeps the reference", () => {
    visit(
      "error=authentication_failed&reason=SSO_MEMBER_NOT_PROVISIONED&message=x&ref=req-123",
    );
    render(<CallbackPage />);

    expect(
      screen.getByText(/no member account for this sign-in/i),
    ).toBeInTheDocument();
    expect(screen.getByText("req-123")).toBeInTheDocument();
    expect(exchangeSsoCodeMock).not.toHaveBeenCalled();
  });

  it("no longer accepts tokens in the URL, and scrubs them", () => {
    visit("token=acc&refreshToken=ref&expiresIn=900");
    render(<CallbackPage />);

    expect(
      screen.getByRole("heading", { name: /incomplete sign-in response/i }),
    ).toBeInTheDocument();
    expect(exchangeSsoCodeMock).not.toHaveBeenCalled();
    expect(establishSessionMock).not.toHaveBeenCalled();
    expect(window.location.search).toBe("");
  });

  it("refuses a callback without a code", () => {
    visit("");
    render(<CallbackPage />);
    expect(
      screen.getByRole("heading", { name: /incomplete sign-in response/i }),
    ).toBeInTheDocument();
    expect(exchangeSsoCodeMock).not.toHaveBeenCalled();
  });
});
