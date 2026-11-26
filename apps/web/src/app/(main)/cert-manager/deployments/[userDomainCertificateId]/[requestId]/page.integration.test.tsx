// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import DeploymentDetailsPage from "@/app/(main)/cert-manager/deployments/[userDomainCertificateId]/[requestId]/page";

const mockUseAuth = jest.fn();
const mockUseDeploymentByRequestId = jest.fn();
const mockUseDeploymentLiveCertificate = jest.fn();
const mockUseDeploymentCredentialReference = jest.fn();

jest.mock("next/navigation", () => ({
  useParams: () => ({
    userDomainCertificateId: "101",
    requestId: "req-1",
  }),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockUseAuth(),
}));

jest.mock("@/hooks/deployments", () => ({
  useDeploymentByRequestId: (requestId: string) =>
    mockUseDeploymentByRequestId(requestId),
  useDeploymentLiveCertificate: (certificateXref?: string) =>
    mockUseDeploymentLiveCertificate(certificateXref),
  useDeploymentCredentialReference: (credentialXref?: string) =>
    mockUseDeploymentCredentialReference(credentialXref),
}));

jest.mock("@/components/common/unautorised", () => ({
  Unauthorised: () => <div>Access Restricted</div>,
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({
    title,
    subtitle,
    actions,
  }: {
    title: string;
    subtitle?: string;
    actions?: React.ReactNode;
  }) => (
    <div>
      <div>{title}</div>
      {subtitle ? <div>{subtitle}</div> : null}
      {actions}
    </div>
  ),
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

describe("deployment request details page integration", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({
      user: {
        id: "u1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: [
          "deployments:view",
          "certificate:read",
          "certificate:deploy",
        ],
        authMethod: "LOCAL",
      },
      isLoading: false,
    });
    mockUseDeploymentLiveCertificate.mockReturnValue({
      isLoading: false,
      isError: false,
      data: null,
    });
    mockUseDeploymentCredentialReference.mockReturnValue({
      isLoading: false,
      isError: false,
      data: null,
    });
  });

  it("renders unauthorized state without deployments permission", () => {
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
    mockUseDeploymentByRequestId.mockReturnValue({
      isLoading: false,
      isError: false,
      data: null,
    });

    renderWithQueryClient(<DeploymentDetailsPage />);
    expect(screen.getByText("Access Restricted")).toBeInTheDocument();
  });

  it("renders not-found state when deployment is missing", () => {
    mockUseDeploymentByRequestId.mockReturnValue({
      isLoading: false,
      isError: false,
      data: null,
    });

    renderWithQueryClient(<DeploymentDetailsPage />);
    expect(screen.getByText("Deployment not found")).toBeInTheDocument();
  });

  it("renders deployment details when request exists", () => {
    mockUseDeploymentByRequestId.mockReturnValue({
      isLoading: false,
      isError: false,
      data: {
        requestId: "req-1",
        userDomainCertId: 101,
        domain: "alpha.example.com",
        certificateXref: "cert-1",
        status: "SUCCESS",
        flowType: "MANUAL",
        targetType: "AKAMAI",
        deploymentCredentialXref: "cred-1",
        requestedAt: "2026-01-01T00:00:00Z",
        createdAt: "2026-01-01T00:00:00Z",
      },
    });

    renderWithQueryClient(<DeploymentDetailsPage />);
    expect(screen.getAllByText("alpha.example.com").length).toBeGreaterThan(0);
    expect(screen.getByText("Execution timeline")).toBeInTheDocument();
  });
});
