// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CredentialSecretPayloadCard } from "@/components/cert-manager/credentials/credential-secret-payload-card";

jest.mock("sonner", () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
  },
}));

import { toast } from "sonner";

describe("CredentialSecretPayloadCard", () => {
  beforeEach(() => {
    (toast.success as jest.Mock).mockClear();
    (toast.error as jest.Mock).mockClear();
  });

  it("pretty-prints JSON templates", () => {
    render(
      <CredentialSecretPayloadCard
        payloadTemplate='{"a":1}'
        providerApiValue=""
      />,
    );

    expect(screen.getByText(/"a": 1/)).toBeInTheDocument();
  });

  it("copies payload and shows toast feedback", async () => {
    const user = userEvent.setup();
    const writeText = jest.fn().mockResolvedValue(undefined);

    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });

    render(
      <CredentialSecretPayloadCard
        payloadTemplate='{"a":1}'
        providerApiValue="AWS_ACM"
      />,
    );

    await user.click(
      screen.getByRole("button", { name: /copy secret template/i }),
    );

    expect(writeText).toHaveBeenCalledWith('{"a":1}');
    expect(toast.success).toHaveBeenCalledWith("Secret template copied");
  });
});
