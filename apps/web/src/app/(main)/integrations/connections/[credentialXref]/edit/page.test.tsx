// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import EditCredentialPage from "@/app/(main)/integrations/connections/[credentialXref]/edit/page";

let mockAgentTransport: "GATEWAY" | undefined;
jest.mock("@/hooks/use-deployment-mode", () => ({
  useAgentTransport: () => mockAgentTransport,
}));

const pushMock = jest.fn();
const refreshMock = jest.fn();
const updateCredentialMock = jest.fn<Promise<unknown>, [unknown]>();
const mockUseCredentialReference = jest.fn();
let mockDnsCredentialsEnabled = true;

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

global.ResizeObserver = ResizeObserverMock;

jest.mock("next/navigation", () => ({
  useParams: () => ({ credentialXref: "cred-aks" }),
  useRouter: () => ({
    push: pushMock,
    refresh: refreshMock,
  }),
}));

jest.mock("@/hooks/credentials", () => ({
  useCredentialReference: () => mockUseCredentialReference(),
  useUpdateCredential: () => ({
    isPending: false,
    mutateAsync: updateCredentialMock,
  }),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) =>
    key !== "DNS_CREDENTIALS" || mockDnsCredentialsEnabled,
}));

jest.mock("@/hooks/use-unsaved-changes-warning", () => ({
  useUnsavedChangesWarning: () => ({
    confirmLeave: () => true,
  }),
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({ title }: { title: string }) => <div>{title}</div>,
}));

jest.mock(
  "@/components/cert-manager/credentials/credential-selected-provider-banner",
  () => ({
    CredentialSelectedProviderBanner: ({ label }: { label: string }) => (
      <div>{label}</div>
    ),
  }),
);

jest.mock(
  "@/components/cert-manager/credentials/credential-provider-info-dialog",
  () => ({
    CredentialProviderInfoDialog: () => null,
  }),
);

describe("EditCredentialPage managed Kubernetes Azure credentials", () => {
  beforeEach(() => {
    pushMock.mockReset();
    refreshMock.mockReset();
    updateCredentialMock.mockReset();
    // A secret pasted into CertPing on an install whose agents use the gateway.
    mockAgentTransport = "GATEWAY";
    mockUseCredentialReference.mockReset();
    mockUseCredentialReference.mockReturnValue({
      data: {
        credentialXref: "cred-aks",
        provider: "KUBERNETES_SECRETS",
        type: "DEPLOYMENT",
        description: "AKS production",
        status: "ACTIVE",
        secretHandle: "local:cred-aks",
        configJson:
          '{"authMethod": "AZURE", "namespaces": ["team-a"], "clusterName": "aks-example"}',
      },
      isLoading: false,
    });
    updateCredentialMock.mockResolvedValue({});
    mockDnsCredentialsEnabled = true;
  });

  it("refuses to edit a DNS provider while DNS credentials are off", () => {
    mockDnsCredentialsEnabled = false;
    mockUseCredentialReference.mockReturnValue({
      data: {
        credentialXref: "cred-cloudflare",
        provider: "CLOUDFLARE",
        type: "DNS",
        description: "Cloudflare production",
        status: "ACTIVE",
        secretHandle: "https://managed-vault/secrets/cred-cloudflare/version",
      },
      isLoading: false,
    });

    render(<EditCredentialPage />);

    expect(
      screen.getByRole("heading", { name: "DNS credentials isn't available" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Save credential" }),
    ).not.toBeInTheDocument();
  });

  it("rotates AKS service principal credentials with the documented payload keys", async () => {
    const user = userEvent.setup();
    render(<EditCredentialPage />);

    await user.type(await screen.findByLabelText("Tenant ID"), "tenant-1");
    expect(
      screen.getByRole("combobox", { name: "Auth method" }),
    ).toHaveTextContent("Azure (AKS)");
    expect(
      screen.queryByText(/store AKS auth metadata in Key Vault/i),
    ).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Subscription ID"), "sub-1");
    await user.type(screen.getByLabelText("Resource group"), "rg-aks");
    await user.type(screen.getByLabelText("Client ID"), "client-1");
    await user.type(screen.getByLabelText("Client secret"), "secret-1");
    await user.click(screen.getByRole("button", { name: "Save credential" }));

    await waitFor(() => expect(updateCredentialMock).toHaveBeenCalledTimes(1));
    expect(updateCredentialMock).toHaveBeenCalledWith({
      credentialXref: "cred-aks",
      configJson: {
        authMethod: "AZURE",
        clusterName: "aks-example",
        namespaces: ["team-a"],
      },
      credJson: {
        azureTenantId: "tenant-1",
        azureSubscriptionId: "sub-1",
        azureResourceGroup: "rg-aks",
        azureClientId: "client-1",
        azureClientSecret: "secret-1",
      },
      secretHandle: null,
    });
  });

  it("updates vault-backed Namecheap credentials without replaying configJson", async () => {
    mockAgentTransport = undefined;
    mockUseCredentialReference.mockReturnValue({
      data: {
        credentialXref: "cred-namecheap",
        provider: "NAMECHEAP",
        type: "DNS",
        description: "Namecheap production",
        status: "ACTIVE",
        secretHandle:
          "https://e2e-vault.vault.azure.net/secrets/e2e-credential/00000000000000000000000000000000",
        configJson: '{"apiUser": "e2e-user", "username": "e2e-user"}',
      },
      isLoading: false,
    });
    const user = userEvent.setup();
    render(<EditCredentialPage />);

    await user.type(
      await screen.findByLabelText("Namecheap API user"),
      "asdad",
    );
    await user.type(screen.getByLabelText("Namecheap username"), "asdad");
    await user.click(screen.getByRole("button", { name: "Save credential" }));

    await waitFor(() => expect(updateCredentialMock).toHaveBeenCalledTimes(1));
    expect(updateCredentialMock).toHaveBeenCalledWith({
      credentialXref: "cred-namecheap",
      secretHandle:
        "https://e2e-vault.vault.azure.net/secrets/e2e-credential/00000000000000000000000000000000",
      credJson: {
        apiUser: "asdad",
        username: "asdad",
      },
    });
  });
});
