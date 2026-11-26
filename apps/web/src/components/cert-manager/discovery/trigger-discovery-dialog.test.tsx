// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { TriggerDiscoveryDialog } from "@/components/cert-manager/discovery/trigger-discovery-dialog";
import {
  AWS_ACM_DISCOVERY_COVERAGE_HELP,
  DISCOVERY_SOURCE_OPTIONS,
} from "@/lib/cert-manager/discovery-display";
import type { CredentialRecord } from "@/types/ssl";

jest.mock("@/hooks/discovery", () => ({
  useTriggerDiscovery: () => ({ mutateAsync: jest.fn(), isPending: false }),
}));

jest.mock("@/hooks/credentials", () => ({
  useCanAddCredential: () => false,
}));

jest.mock("@/components/common/provider-icon", () => ({
  ProviderIcon: () => <span data-testid="provider-icon" />,
}));

function credential(targetType: string): CredentialRecord {
  return {
    alias: `cred-${targetType}`,
    credentialXref: `cred-${targetType}`,
    description: `Target ${targetType}`,
    targetType,
    type: "DEPLOYMENT",
  } as CredentialRecord;
}

const OFFERED = [
  "AWS_ACM",
  "AWS_ORGANIZATION",
  "AZURE_KV",
  "KUBERNETES_SECRETS",
];
const NOT_DISCOVERED = [
  "AZURE_APP_GW",
  "AZURE_AFD",
  "AZURE_APP_GW_CONTAINERS",
  "GCP_CERT_MANAGER",
  "GCP_ALB",
  "GCP_PROXY_NLB",
  "GCP_API_GW",
  "GCP_CLOUD_CDN",
  "AWS_ALB",
  "AWS_NLB",
  "AWS_CLOUDFRONT",
  "AWS_API_GW_REST",
  "AWS_API_GW_HTTP",
];

describe("TriggerDiscoveryDialog", () => {
  it("lists only AWS ACM (region), AWS Organization ACM, Azure Key Vault and Kubernetes", () => {
    expect(
      DISCOVERY_SOURCE_OPTIONS.map((option) => option.value).sort(),
    ).toEqual([...OFFERED].sort());
    expect(DISCOVERY_SOURCE_OPTIONS.map((option) => option.label)).toEqual([
      "AWS Organization ACM",
      "AWS ACM (region)",
      "Azure Key Vault",
      "Kubernetes Secrets",
    ]);
  });

  it("offers only credentials the agent really discovers", async () => {
    const user = userEvent.setup();
    render(
      <TriggerDiscoveryDialog
        open
        onOpenChange={jest.fn()}
        credentials={[...NOT_DISCOVERED, ...OFFERED].map(credential)}
      />,
    );

    await user.click(
      screen.getByRole("combobox", { name: "Select a deployment target" }),
    );
    const listbox = await screen.findByRole("listbox");
    const options = within(listbox).getAllByRole("option");
    expect(options).toHaveLength(OFFERED.length);
    for (const type of OFFERED) {
      expect(within(listbox).getByText(`Target ${type}`)).toBeInTheDocument();
    }
    for (const type of NOT_DISCOVERED) {
      expect(within(listbox).queryByText(`Target ${type}`)).toBeNull();
    }
  });

  it("explains that ACM discovery covers ALB, NLB, CloudFront and API Gateway", () => {
    render(
      <TriggerDiscoveryDialog
        open
        onOpenChange={jest.fn()}
        credentials={[credential("AWS_ACM")]}
      />,
    );
    expect(
      screen.getByText(
        (_, element) =>
          element?.tagName === "P" &&
          (element.textContent ?? "").includes(AWS_ACM_DISCOVERY_COVERAGE_HELP),
      ),
    ).toBeInTheDocument();
  });

  it("shows the empty state when only undiscoverable targets exist", () => {
    render(
      <TriggerDiscoveryDialog
        open
        onOpenChange={jest.fn()}
        credentials={NOT_DISCOVERED.map(credential)}
      />,
    );
    expect(
      screen.getByText("No credentials available for discovery"),
    ).toBeInTheDocument();
  });

  it("marks beta discovery sources and leaves Kubernetes unmarked", () => {
    render(
      <TriggerDiscoveryDialog
        open
        onOpenChange={jest.fn()}
        credentials={[credential("KUBERNETES_SECRETS")]}
      />,
    );
    expect(screen.queryByTestId("beta-badge")).toBeNull();
  });
});
