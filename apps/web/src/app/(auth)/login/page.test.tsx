// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import type { SignedOutReason } from "@/lib/signed-out-reason";
import LoginPage from "./page";

jest.mock("@/components/auth/setup-redirect", () => ({
  SetupRedirect: () => <span data-testid="setup-redirect" />,
}));

jest.mock("./ent-login-form", () => ({
  __esModule: true,
  default: ({
    signedOutReason,
  }: {
    signedOutReason: SignedOutReason | null;
  }) => <p>{`local sign-in, reason ${String(signedOutReason)}`}</p>,
}));

async function renderLoginPage(params: Record<string, string>) {
  render(await LoginPage({ searchParams: Promise.resolve(params) }));
}

describe("LoginPage", () => {
  it.each(["account-disabled", "organization-suspended"])(
    "passes the signed-out reason %s to the local sign-in form",
    async (reason) => {
      await renderLoginPage({ signedOut: reason });
      expect(
        screen.getByText(`local sign-in, reason ${reason}`),
      ).toBeInTheDocument();
    },
  );

  it("checks whether first-run setup is still needed", async () => {
    await renderLoginPage({});
    expect(screen.getByTestId("setup-redirect")).toBeInTheDocument();
  });

  it("drops an unknown reason", async () => {
    await renderLoginPage({ signedOut: "<script>" });
    expect(screen.getByText("local sign-in, reason null")).toBeInTheDocument();
  });
});
