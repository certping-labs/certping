// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { MfaSection, formatSecretForDisplay } from "./mfa-section";

const getMfaStatusMock = jest.fn();
const startMfaEnrollmentMock = jest.fn();
const confirmMfaEnrollmentMock = jest.fn();
const disableMfaMock = jest.fn();

jest.mock("@/lib/backend/auth", () => ({
  getMfaStatus: () => getMfaStatusMock(),
  startMfaEnrollment: () => startMfaEnrollmentMock(),
  confirmMfaEnrollment: (payload: unknown) => confirmMfaEnrollmentMock(payload),
  disableMfa: (payload: unknown) => disableMfaMock(payload),
}));
jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

function renderSection() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MfaSection />
    </QueryClientProvider>,
  );
}

describe("MfaSection", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("groups the secret in fours", () => {
    expect(formatSecretForDisplay("ABCDEFGHIJKLMNOP")).toBe(
      "ABCD EFGH IJKL MNOP",
    );
  });

  it("enrolls, confirms with a code and shows the recovery codes once", async () => {
    getMfaStatusMock
      .mockResolvedValueOnce({
        enabled: false,
        confirmedAt: null,
        recoveryCodesRemaining: 0,
      })
      .mockResolvedValue({
        enabled: true,
        confirmedAt: "2026-10-25T12:00:00Z",
        recoveryCodesRemaining: 8,
      });
    startMfaEnrollmentMock.mockResolvedValue({
      secret: "JBSWY3DPEHPK3PXP",
      otpauthUri:
        "otpauth://totp/CertPing:ada?secret=JBSWY3DPEHPK3PXP&issuer=CertPing",
    });
    confirmMfaEnrollmentMock.mockResolvedValue({
      message: "on",
      recoveryCodes: ["abcde-fghij", "klmno-pqrst"],
    });
    renderSection();

    expect(await screen.findByText("Off")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: /set up authenticator app/i }),
    );

    expect(await screen.findByTestId("mfa-secret")).toHaveTextContent(
      "JBSW Y3DP EHPK 3PXP",
    );
    expect(screen.getByTitle("Authenticator setup code")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /open in authenticator app/i }),
    ).toHaveAttribute("href", expect.stringContaining("otpauth://totp/"));
    fireEvent.change(screen.getByLabelText(/code from the app/i), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));

    await waitFor(() =>
      expect(confirmMfaEnrollmentMock).toHaveBeenCalledWith({ code: "123456" }),
    );
    const codes = await screen.findByTestId("mfa-recovery-codes");
    expect(codes).toHaveTextContent("abcde-fghij");
    expect(codes).toHaveTextContent("klmno-pqrst");
    expect(await screen.findByText("On")).toBeInTheDocument();
    expect(screen.getByText(/8 recovery codes left/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /i saved them/i }));
    expect(screen.queryByTestId("mfa-recovery-codes")).not.toBeInTheDocument();
  });

  it("turns the factor off only with the password", async () => {
    getMfaStatusMock
      .mockResolvedValueOnce({
        enabled: true,
        confirmedAt: "2026-10-25T12:00:00Z",
        recoveryCodesRemaining: 1,
      })
      .mockResolvedValue({
        enabled: false,
        confirmedAt: null,
        recoveryCodesRemaining: 0,
      });
    disableMfaMock.mockResolvedValue(undefined);
    renderSection();

    expect(await screen.findByText("On")).toBeInTheDocument();
    expect(screen.getByText(/1 recovery code left/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));

    const submit = screen.getByRole("button", {
      name: /turn off two-factor authentication/i,
    });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "hunter2hunter2" },
    });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    await waitFor(() =>
      expect(disableMfaMock).toHaveBeenCalledWith({
        password: "hunter2hunter2",
      }),
    );
    expect(await screen.findByText("Off")).toBeInTheDocument();
  });
});
