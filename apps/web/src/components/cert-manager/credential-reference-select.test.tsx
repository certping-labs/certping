// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  CredentialReferenceMultiSelect,
  CredentialReferenceSelect,
} from "@/components/cert-manager/credential-reference-select";
import type { CredentialRecord } from "@/types/ssl";

const pushMock = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img {...props} alt={props.alt ?? ""} />
  ),
}));

const credential = {
  alias: "dns-prod",
  credentialXref: "dns-prod",
  description: "Production DNS",
  providerName: "CLOUDFLARE",
} as CredentialRecord;

describe("CredentialReferenceSelect", () => {
  beforeEach(() => {
    pushMock.mockReset();
  });

  it("always offers the add action and routes without changing the field", async () => {
    const user = userEvent.setup();
    const onValueChange = jest.fn();

    render(
      <CredentialReferenceSelect
        addCredentialHref="/integrations/connections/add?type=DNS"
        addCredentialLabel="Connect DNS provider"
        credentials={[credential]}
        onValueChange={onValueChange}
        placeholder="Select DNS credential"
      />,
    );

    await user.click(screen.getByRole("combobox"));
    await user.click(
      await screen.findByRole("option", { name: "Connect DNS provider" }),
    );

    expect(pushMock).toHaveBeenCalledWith(
      "/integrations/connections/add?type=DNS",
    );
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it("resolves a lazy add link when it is chosen", async () => {
    const user = userEvent.setup();
    let domain = "a.example.com";

    render(
      <CredentialReferenceSelect
        addCredentialHref={() => `/connect?returnTo=${domain}`}
        addCredentialLabel="Connect DNS provider"
        credentials={[]}
        onValueChange={jest.fn()}
        placeholder="Select DNS credential"
      />,
    );

    domain = "b.example.com";
    await user.click(screen.getByRole("combobox"));
    await user.click(
      await screen.findByRole("option", { name: "Connect DNS provider" }),
    );

    expect(pushMock).toHaveBeenCalledWith("/connect?returnTo=b.example.com");
  });

  it("shows the add action even when no credentials exist", async () => {
    const user = userEvent.setup();

    render(
      <CredentialReferenceSelect
        addCredentialHref="/integrations/connections/add?type=DEPLOYMENT"
        addCredentialLabel="Add deployment target"
        credentials={[]}
        onValueChange={jest.fn()}
        placeholder="Select deployment credential"
      />,
    );

    await user.click(screen.getByRole("combobox"));

    expect(
      await screen.findByRole("option", {
        name: "Add deployment target",
      }),
    ).toBeInTheDocument();
  });

  it("exposes the credential xref for deterministic option selection", async () => {
    const user = userEvent.setup();

    render(
      <CredentialReferenceSelect
        credentials={[credential]}
        onValueChange={jest.fn()}
        placeholder="Select DNS credential"
      />,
    );

    await user.click(screen.getByRole("combobox"));

    expect(
      await screen.findByRole("option", {
        name: "Production DNS (Cloudflare)",
      }),
    ).toHaveAttribute("data-value", credential.credentialXref);
  });

  it("marks credentials whose provider has no end-to-end test as Beta", async () => {
    const user = userEvent.setup();
    const k8s = {
      alias: "k8s-prod",
      credentialXref: "k8s-prod",
      description: "Prod cluster",
      targetType: "KUBERNETES_SECRETS",
    } as CredentialRecord;

    render(
      <CredentialReferenceSelect
        credentials={[credential, k8s]}
        onValueChange={jest.fn()}
        placeholder="Select credential"
      />,
    );

    await user.click(screen.getByRole("combobox"));
    const cloudflare = await screen.findByRole("option", {
      name: "Production DNS (Cloudflare)",
    });
    expect(within(cloudflare).getByTestId("beta-badge")).toHaveTextContent(
      "Beta",
    );
    const cluster = screen.getByRole("option", { name: /Prod cluster/ });
    expect(within(cluster).queryByTestId("beta-badge")).toBeNull();
  });

  it("exposes the trigger through its associated label", () => {
    render(
      <>
        <label htmlFor="credential-reference">Deployment credential</label>
        <CredentialReferenceSelect
          id="credential-reference"
          credentials={[credential]}
          onValueChange={jest.fn()}
          placeholder="Select deployment credential"
        />
      </>,
    );

    expect(
      screen.getByRole("combobox", { name: "Deployment credential" }),
    ).toBeInTheDocument();
  });
});

describe("CredentialReferenceMultiSelect", () => {
  it("routes from its persistent add action when the credential list is empty", async () => {
    const user = userEvent.setup();

    render(
      <CredentialReferenceMultiSelect
        addCredentialHref="/integrations/connections/add?type=DEPLOYMENT"
        addCredentialLabel="Add deployment target"
        credentials={[]}
        onValueChange={jest.fn()}
        placeholder="Select deployment targets"
        value={[]}
      />,
    );

    await user.click(screen.getByRole("combobox"));
    await user.click(
      screen.getByRole("button", { name: "Add deployment target" }),
    );

    expect(pushMock).toHaveBeenCalledWith(
      "/integrations/connections/add?type=DEPLOYMENT",
    );
  });
});
