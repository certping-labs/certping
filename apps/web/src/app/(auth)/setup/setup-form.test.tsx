// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { SetupForm } from "./setup-form";

const replaceMock = jest.fn();
const getSetupStatusMock = jest.fn();
const completeFirstRunSetupMock = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
}));
jest.mock("@/lib/backend/auth", () => ({
  getSetupStatus: () => getSetupStatusMock(),
  completeFirstRunSetup: (payload: unknown) =>
    completeFirstRunSetupMock(payload),
}));
jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));
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

function renderForm() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <SetupForm />
    </QueryClientProvider>,
  );
}

function fill(
  values: Partial<
    Record<"username" | "email" | "password" | "confirmPassword", string>
  >,
) {
  const set = (label: RegExp, value: string) =>
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  set(/^username$/i, values.username ?? "owner");
  set(/^email$/i, values.email ?? "owner@example.com");
  set(/^password$/i, values.password ?? "Correct-Horse-Battery-9");
  set(
    /^confirm password$/i,
    values.confirmPassword ?? values.password ?? "Correct-Horse-Battery-9",
  );
}

describe("SetupForm", () => {
  beforeEach(() => {
    replaceMock.mockReset();
    getSetupStatusMock.mockReset();
    completeFirstRunSetupMock.mockReset();
    getSetupStatusMock.mockResolvedValue({ setupRequired: true });
  });

  it("creates the first Platform Super Admin and sends the user to sign in", async () => {
    completeFirstRunSetupMock.mockResolvedValue({
      message: "done",
      username: "owner",
      email: "owner@example.com",
    });
    renderForm();

    await screen.findByRole("form", { name: "First-run setup" });
    fill({});
    fireEvent.click(
      screen.getByRole("button", { name: "Create Platform Super Admin" }),
    );

    await waitFor(() =>
      expect(completeFirstRunSetupMock).toHaveBeenCalledWith({
        displayName: undefined,
        username: "owner",
        email: "owner@example.com",
        password: "Correct-Horse-Battery-9",
      }),
    );
    await waitFor(() =>
      expect(replaceMock).toHaveBeenCalledWith("/login?setup=done"),
    );
  });

  it("refuses mismatched or short passwords before calling the server", async () => {
    renderForm();
    await screen.findByRole("form", { name: "First-run setup" });

    fill({
      password: "Correct-Horse-Battery-9",
      confirmPassword: "different-password-1",
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create Platform Super Admin" }),
    );
    expect(screen.getByRole("alert")).toHaveTextContent("do not match");

    fill({ password: "short", confirmPassword: "short" });
    fireEvent.click(
      screen.getByRole("button", { name: "Create Platform Super Admin" }),
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "at least 12 characters",
    );
    expect(completeFirstRunSetupMock).not.toHaveBeenCalled();
  });

  it("shows the server's answer when setup is refused or invalid", async () => {
    const { AxiosError } = jest.requireActual("axios");
    completeFirstRunSetupMock.mockRejectedValue(
      new AxiosError("Conflict", "ERR_BAD_REQUEST", undefined, undefined, {
        status: 409,
        statusText: "Conflict",
        headers: {},
        config: { headers: {} },
        data: { message: "Setup has already been completed" },
      } as never),
    );
    renderForm();
    await screen.findByRole("form", { name: "First-run setup" });

    fill({});
    fireEvent.click(
      screen.getByRole("button", { name: "Create Platform Super Admin" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Setup has already been completed",
    );
    expect(replaceMock).not.toHaveBeenCalled();
  });

  it("redirects to sign in once setup is no longer required", async () => {
    getSetupStatusMock.mockResolvedValue({ setupRequired: false });
    renderForm();
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/login"));
    expect(screen.queryByRole("form")).toBeNull();
  });

  it("explains when the server cannot be reached", async () => {
    getSetupStatusMock.mockRejectedValue(new Error("network"));
    renderForm();
    expect(
      await screen.findByText(
        "CertPing server not reachable",
        {},
        { timeout: 4000 },
      ),
    ).toBeInTheDocument();
  });
});
