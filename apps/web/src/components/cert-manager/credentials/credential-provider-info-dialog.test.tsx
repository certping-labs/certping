// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CredentialProviderInfoDialog } from "@/components/cert-manager/credentials/credential-provider-info-dialog";

const originalAppMode = process.env.NEXT_PUBLIC_APP_MODE;

describe("CredentialProviderInfoDialog", () => {
  afterEach(() => {
    process.env.NEXT_PUBLIC_APP_MODE = originalAppMode;
  });

  it("shows provider-specific setup guidance without internal field names", async () => {
    const user = userEvent.setup();
    render(<CredentialProviderInfoDialog providerApiValue="AWS_ACM" />);

    await user.click(
      screen.getByRole("button", { name: /open credential setup guidance/i }),
    );

    expect(screen.getByText(/acm:ImportCertificate/i)).toBeInTheDocument();
    expect(screen.queryByText(/configJson/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secretHandle/i)).not.toBeInTheDocument();
  });

  it("shows actionable Kubernetes permission guidance", async () => {
    const user = userEvent.setup();
    render(
      <CredentialProviderInfoDialog providerApiValue="KUBERNETES_SECRETS" />,
    );

    await user.click(
      screen.getByRole("button", { name: /open credential setup guidance/i }),
    );

    expect(
      screen.getByText(/Kubernetes secret-writer RBAC/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/docs\/kubernetes/i)).not.toBeInTheDocument();
  });

  it("shows selected AKS role and Kubernetes RBAC guidance", async () => {
    const user = userEvent.setup();
    render(
      <CredentialProviderInfoDialog
        kubernetesAuthMethod="AZURE"
        providerApiValue="KUBERNETES_SECRETS"
      />,
    );

    await user.click(
      screen.getByRole("button", { name: /open credential setup guidance/i }),
    );

    expect(screen.getByText(/Azure \(AKS\)/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Azure Kubernetes Service Cluster User Role/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/get, create, update, and delete secrets/i),
    ).toBeInTheDocument();
  });

  it("shows provider setup guidance for Akamai", async () => {
    const user = userEvent.setup();
    render(<CredentialProviderInfoDialog providerApiValue="AKAMAI_CPS" />);

    await user.click(
      screen.getByRole("button", { name: /open credential setup guidance/i }),
    );

    expect(
      screen.getByText(/EdgeGrid API client authorized/i),
    ).toBeInTheDocument();
  });
});
