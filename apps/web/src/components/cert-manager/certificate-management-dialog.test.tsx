// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";

import { CertificateManagementDialog } from "@/components/cert-manager/certificate-management-dialog";
import type { CredentialRecord, SSLCertificateListItem } from "@/types/ssl";

const mockFlags = jest.fn<boolean, [string]>();
const mockRouteAvailable = jest.fn<boolean, [string]>();
const mockCredentials = jest.fn<CredentialRecord[], []>();

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) => mockFlags(key),
  useIsRouteAvailable: () => (href: string) => mockRouteAvailable(href),
}));

jest.mock("@/hooks/credentials", () => ({
  useCredentials: ({ category }: { category: string }) => ({
    data: category === "dns_credential" ? mockCredentials() : [],
    isLoading: false,
  }),
  useCanAddCredential: () => true,
}));

jest.mock("@/hooks/certificate-config", () => ({
  useSyncCertificateCredentialConfig: () => ({
    mutateAsync: jest.fn(),
    isPending: false,
  }),
}));

jest.mock("@/hooks/ssl", () => ({
  useConvertCertificateToAutomated: () => ({
    mutateAsync: jest.fn(),
    isPending: false,
  }),
}));

jest.mock("@/components/cert-manager/credential-reference-trigger", () => ({
  CredentialReferenceTrigger: () => null,
}));

jest.mock("@/components/cert-manager/credential-reference-select", () => ({
  CredentialReferenceSelect: ({
    credentials,
    addCredentialHref,
  }: {
    credentials: CredentialRecord[];
    addCredentialHref?: string;
  }) => (
    <div data-testid="dns-picker">
      {credentials.map((credential) => (
        <span key={credential.credentialXref}>{credential.description}</span>
      ))}
      {addCredentialHref ? (
        <a href={addCredentialHref}>Connect DNS provider</a>
      ) : null}
    </div>
  ),
  CredentialReferenceMultiSelect: () => <div data-testid="deployment-picker" />,
}));

const credential = (
  xref: string,
  provider: string,
  description: string,
): CredentialRecord =>
  ({
    credentialXref: xref,
    alias: xref,
    providerName: provider,
    description,
    category: "dns_credential",
    status: "ACTIVE",
  }) as CredentialRecord;

const manualCertificate: SSLCertificateListItem = {
  certificateXref: "cert-1",
  domain: "shop.example.com",
  status: "VALIDATING",
  managementState: "manual",
};

function renderDialog(certificate: SSLCertificateListItem = manualCertificate) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <CertificateManagementDialog
        certificate={certificate}
        open
        onOpenChange={jest.fn()}
      />
    </QueryClientProvider>,
  );
}

describe("CertificateManagementDialog", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFlags.mockReturnValue(true);
    mockRouteAvailable.mockReturnValue(true);
    mockCredentials.mockReturnValue([
      credential("cred-cp", "CERTPING", "example.com"),
      credential("cred-cf", "CLOUDFLARE", "Cloudflare account"),
    ]);
  });

  it("offers every DNS credential and the integration links while they are on", () => {
    renderDialog();

    const picker = screen.getByTestId("dns-picker");
    expect(picker).toHaveTextContent("example.com");
    expect(picker).toHaveTextContent("Cloudflare account");
    expect(
      screen.getByRole("link", { name: "Connect DNS provider" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Manage integrations" }),
    ).toBeInTheDocument();
  });

  it("keeps the certificate's current third-party credential listed while DNS credentials are off", () => {
    mockFlags.mockImplementation((key) => key !== "DNS_CREDENTIALS");
    mockCredentials.mockReturnValue([
      credential("cred-cp", "CERTPING", "example.com"),
      credential("cred-cf", "CLOUDFLARE", "Cloudflare account"),
      credential("cred-r53", "AWS_ROUTE53", "Route 53 account"),
    ]);

    renderDialog({ ...manualCertificate, dnsConfigXref: "cred-cf" });

    const picker = screen.getByTestId("dns-picker");
    expect(picker).toHaveTextContent("Cloudflare account");
    expect(picker).not.toHaveTextContent("Route 53 account");
  });

  it("links to no integrations page that is off", () => {
    mockRouteAvailable.mockImplementation(
      (href) => !href.startsWith("/integrations/"),
    );

    renderDialog();

    expect(
      screen.queryByRole("link", { name: "Connect DNS provider" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Manage integrations" }),
    ).not.toBeInTheDocument();
  });

  it("keeps pointing to the selectors while a deployment credential can still be added", () => {
    mockFlags.mockImplementation((key) => key !== "DNS_CREDENTIALS");
    mockRouteAvailable.mockImplementation((href) =>
      href.includes("type=DEPLOYMENT"),
    );
    mockCredentials.mockReturnValue([
      credential("cred-cf", "CLOUDFLARE", "Cloudflare account"),
    ]);

    renderDialog();

    expect(
      screen.getByText(
        "Use the credential selectors above to add the required DNS provider or deployment target.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        "This feature isn't available. To request access, ask your CertPing administrator.",
      ),
    ).not.toBeInTheDocument();
  });

  it("says it isn't available when there is no credential to choose and none can be added", () => {
    mockFlags.mockImplementation((key) => key !== "DNS_CREDENTIALS");
    mockRouteAvailable.mockReturnValue(false);
    mockCredentials.mockReturnValue([
      credential("cred-cf", "CLOUDFLARE", "Cloudflare account"),
    ]);

    renderDialog();

    expect(
      screen.getByText(
        "This feature isn't available. To request access, ask your CertPing administrator.",
      ),
    ).toBeInTheDocument();
  });
});
