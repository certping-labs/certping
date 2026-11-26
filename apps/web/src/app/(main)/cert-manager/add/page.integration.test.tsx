// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import AddCertificatePage from "@/app/(main)/cert-manager/add/page";

const mockUseAuth = jest.fn();

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockUseAuth(),
}));

let mockSearchParams: URLSearchParams | null = new URLSearchParams();
jest.mock("next/navigation", () => ({
  useSearchParams: () => mockSearchParams,
}));

const mockUseGetCertificateDetails = jest.fn();
jest.mock("@/hooks/ssl", () => ({
  useGetCertificateDetails: (id: string) => mockUseGetCertificateDetails(id),
}));

jest.mock("@/components/cert-manager/add-domain-form", () => ({
  CertificateRequestForm: ({
    initialDomain,
    initialValues,
    sourceCertificateXref,
  }: {
    initialDomain?: string;
    initialValues?: Record<string, unknown>;
    sourceCertificateXref?: string;
  }) => (
    <div>
      Certificate Request Form
      {initialDomain ? <span>for {initialDomain}</span> : null}
      {initialValues ? (
        <span>prefill:{JSON.stringify(initialValues)}</span>
      ) : null}
      {sourceCertificateXref ? (
        <span>source:{sourceCertificateXref}</span>
      ) : null}
    </div>
  ),
}));

jest.mock("@/components/ui/loading-templates", () => ({
  CertManagerPageLoading: () => <div>Loading certificate page</div>,
}));
jest.mock("@/components/common/unautorised", () => ({
  Unauthorised: () => <div>Access Restricted</div>,
}));

const renderWithQueryClient = (ui: React.ReactElement) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
};

describe("add certificate page integration", () => {
  beforeEach(() => {
    mockUseGetCertificateDetails.mockReset();
    mockUseGetCertificateDetails.mockReturnValue({
      data: undefined,
      isLoading: false,
    });
  });

  const issuer = {
    id: "u1",
    email: "user@example.com",
    organizationId: "org-1",
    organizationName: "Org",
    roles: ["USER"],
    permissions: ["certificate:issue"],
    authMethod: "LOCAL",
  };

  it("prefills from the certificate named in ?from= once it loads", () => {
    mockSearchParams = new URLSearchParams({
      from: "cert-old",
      domain: "fallback.example.com",
    });
    mockUseAuth.mockReturnValue({ user: issuer, isLoading: false });
    mockUseGetCertificateDetails.mockReturnValue({
      isLoading: false,
      data: {
        domain: "shop.example.com",
        status: "FAILED",
        wildcard: true,
        caProvider: "DIGICERT",
        dnsConfigXref: "dns-1",
        deploymentCredentialXrefs: ["deploy-1"],
      },
    });

    renderWithQueryClient(<AddCertificatePage />);

    expect(mockUseGetCertificateDetails).toHaveBeenCalledWith("cert-old");
    const prefill = screen.getByText(/^prefill:/).textContent ?? "";
    expect(JSON.parse(prefill.replace("prefill:", ""))).toEqual(
      expect.objectContaining({
        domain: "shop.example.com",
        wildcard: true,
        caProvider: "DIGICERT",
        mode: "automated",
        dnsCredentialXref: "dns-1",
        deploymentTargets: ["deploy-1"],
      }),
    );
    expect(screen.getByText("source:cert-old")).toBeInTheDocument();
    mockSearchParams = new URLSearchParams();
  });

  it("waits for the source certificate before showing the form", () => {
    mockSearchParams = new URLSearchParams({ from: "cert-old" });
    mockUseAuth.mockReturnValue({ user: issuer, isLoading: false });
    mockUseGetCertificateDetails.mockReturnValue({
      data: undefined,
      isLoading: true,
    });

    renderWithQueryClient(<AddCertificatePage />);

    expect(screen.getByText("Loading certificate page")).toBeInTheDocument();
    mockSearchParams = new URLSearchParams();
  });

  it("falls back to the handed-over domain when the source cannot load", () => {
    mockSearchParams = new URLSearchParams({
      from: "cert-gone",
      domain: "shop.example.com",
      wildcard: "1",
    });
    mockUseAuth.mockReturnValue({ user: issuer, isLoading: false });

    renderWithQueryClient(<AddCertificatePage />);

    expect(
      screen.getByText('prefill:{"domain":"shop.example.com","wildcard":true}'),
    ).toBeInTheDocument();
    mockSearchParams = new URLSearchParams();
  });

  it("does not read a source certificate without issue access", () => {
    mockSearchParams = new URLSearchParams({ from: "cert-old" });
    mockUseAuth.mockReturnValue({
      user: { ...issuer, permissions: ["certificate:read"] },
      isLoading: false,
    });

    renderWithQueryClient(<AddCertificatePage />);

    expect(mockUseGetCertificateDetails).toHaveBeenCalledWith("");
    mockSearchParams = new URLSearchParams();
  });

  it("renders loading state while auth resolves", () => {
    mockUseAuth.mockReturnValue({
      user: null,
      isLoading: true,
    });

    renderWithQueryClient(<AddCertificatePage />);
    expect(screen.getByText("Loading certificate page")).toBeInTheDocument();
  });

  it("renders unauthorized state without create permission", () => {
    mockUseAuth.mockReturnValue({
      user: {
        id: "u1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
      },
      isLoading: false,
    });

    renderWithQueryClient(<AddCertificatePage />);
    expect(screen.getByText("Access Restricted")).toBeInTheDocument();
  });

  it("renders certificate request form with create permission", () => {
    mockUseAuth.mockReturnValue({
      user: {
        id: "u1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["certificate:issue"],
        authMethod: "LOCAL",
      },
      isLoading: false,
    });

    renderWithQueryClient(<AddCertificatePage />);
    expect(screen.getByText("Certificate Request Form")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Certificates that use a connected DNS provider renew automatically, and redeploy to the deployment targets you add.",
      ),
    ).toBeInTheDocument();
  });

  it.each([
    ["Example.com", "for example.com"],
    ["<b>bad</b>", null],
  ])(
    "prefills the domain handed over in ?domain=%p only when it is a hostname",
    (domain, expected) => {
      mockSearchParams = new URLSearchParams({ domain });
      mockUseAuth.mockReturnValue({
        user: {
          id: "u1",
          email: "user@example.com",
          organizationId: "org-1",
          organizationName: "Org",
          roles: ["USER"],
          permissions: ["certificate:issue"],
          authMethod: "LOCAL",
        },
        isLoading: false,
      });

      renderWithQueryClient(<AddCertificatePage />);

      if (expected) {
        expect(screen.getByText(expected)).toBeInTheDocument();
      } else {
        expect(screen.queryByText(/^for /)).not.toBeInTheDocument();
      }
      mockSearchParams = new URLSearchParams();
    },
  );
});
