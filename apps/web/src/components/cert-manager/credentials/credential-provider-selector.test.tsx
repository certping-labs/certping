// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CredentialProviderSelector } from "@/components/cert-manager/credentials/credential-provider-selector";
import { getCredentialReferenceProviderOptions } from "@/lib/credential-providers";

jest.mock("next/image", () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) => (
    // eslint-disable-next-line @next/next/no-img-element
    <img {...props} alt={props.alt ?? ""} />
  ),
}));

// Tested end to end today (docs/integrations.md): Kubernetes Secret
// deployment and the CertPing DNS provider. Every other card is beta.
const TESTED_LABELS = new Set(["Kubernetes Secrets", "CertPing DNS"]);

function cards(): HTMLElement[] {
  return screen.getAllByRole("button");
}

describe("CredentialProviderSelector beta labels", () => {
  it.each(["DEPLOYMENT", "DNS"] as const)(
    "every %s adapter without an end-to-end test shows Beta",
    (type) => {
      render(
        <CredentialProviderSelector
          options={getCredentialReferenceProviderOptions(type)}
          selectedProviderApiValue=""
          onSelectProvider={jest.fn()}
        />,
      );

      const all = cards();
      expect(all.length).toBeGreaterThan(0);
      for (const card of all) {
        const name = card.textContent?.replace(/Beta$/, "").trim() ?? "";
        const hasBeta = within(card).queryByTestId("beta-badge") !== null;
        expect([name, hasBeta]).toEqual([name, !TESTED_LABELS.has(name)]);
      }
    },
  );

  it("keeps the Beta badge out of the accessible name", () => {
    render(
      <CredentialProviderSelector
        options={getCredentialReferenceProviderOptions("DEPLOYMENT")}
        selectedProviderApiValue=""
        onSelectProvider={jest.fn()}
      />,
    );
    expect(
      screen.getByRole("button", { name: "Azure Key Vault" }),
    ).toHaveAttribute("title", expect.stringMatching(/^Beta:/));
    expect(
      screen.getByRole("button", { name: "Kubernetes Secrets" }),
    ).not.toHaveAttribute("title");
  });

  it("labels each choice inside a grouped card", async () => {
    const user = userEvent.setup();
    render(
      <CredentialProviderSelector
        options={getCredentialReferenceProviderOptions("DEPLOYMENT")}
        selectedProviderApiValue=""
        onSelectProvider={jest.fn()}
      />,
    );
    await user.click(screen.getByRole("button", { name: "AWS Load Balancer" }));
    const dialog = await screen.findByRole("dialog");
    const choice = within(dialog).getByRole("button", {
      name: "AWS Application Load Balancer",
    });
    expect(within(choice).getByTestId("beta-badge")).toHaveTextContent("Beta");
  });
});
