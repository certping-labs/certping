// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CertificateDetails } from "@/components/cert-manager/certificate/cert-page";
import type { SSLCertificateDetails } from "@/types/ssl";

const mockUseAuth = jest.fn();
const mockUseIsFeatureEnabled = jest.fn();
const mockRenewMutate = jest.fn();
const mockRevokeMutateAsync = jest.fn();
const mockDeleteMutateAsync = jest.fn();
const mockGetTxtRecordsMutateAsync = jest.fn();
const mockValidateDnsMutateAsync = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn() }),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockUseAuth(),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) => mockUseIsFeatureEnabled(key),
  useIsOrgFeatureEnabled: (key: string) => mockUseIsFeatureEnabled(key),
}));

jest.mock("@/hooks/ssl", () => ({
  useCompleteDnsChallenge: () => ({
    isPending: false,
    mutateAsync: mockValidateDnsMutateAsync,
  }),
  useDeletePendingSSLCertificate: () => ({
    mutateAsync: mockDeleteMutateAsync,
  }),
  useGetTxtRecords: () => ({
    mutateAsync: mockGetTxtRecordsMutateAsync,
  }),
  useRenewCertificate: () => ({
    mutate: mockRenewMutate,
  }),
  useRevokeCertificate: () => ({
    mutateAsync: mockRevokeMutateAsync,
  }),
}));

jest.mock("@/components/cert-manager/certificate-management-dialog", () => ({
  CertificateManagementDialog: ({ open }: { open: boolean }) =>
    open ? <div>Management dialog open</div> : null,
  CertificateManagementSummaryCard: ({
    actionLabel,
    canManage,
    onManage,
  }: {
    actionLabel?: string;
    canManage: boolean;
    onManage: () => void;
  }) => (
    <section aria-label="Automation summary">
      {canManage ? (
        <button type="button" onClick={onManage}>
          {actionLabel}
        </button>
      ) : null}
    </section>
  ),
}));

jest.mock("@/components/cert-manager/deploy-new-cert-dialog", () => ({
  DeployNewCertDialog: ({
    initialCertificateId,
    open,
  }: {
    initialCertificateId?: string;
    open: boolean;
  }) =>
    open ? (
      <div data-testid="deploy-dialog">
        Deploying {initialCertificateId ?? "none"}
      </div>
    ) : null,
}));

jest.mock("@/components/cert-manager/certificate/cert-details", () => ({
  CertDetailss: () => <div>Certificate details</div>,
}));

jest.mock("@/components/cert-manager/certificate/cert-deployments", () => ({
  CertDeployments: ({
    canDeployCurrentCert,
    onDeploy,
  }: {
    canDeployCurrentCert: boolean;
    onDeploy: () => void;
  }) => (
    <div>
      {canDeployCurrentCert ? (
        <button type="button" onClick={onDeploy}>
          Deploy from deployments tab
        </button>
      ) : null}
    </div>
  ),
}));

jest.mock("@/components/cert-manager/certificate/cert-history", () => ({
  CertHistory: () => <div>Lifecycle history</div>,
}));

jest.mock("@/components/cert-manager/manual-txt-records-dialog", () => ({
  ManualTxtRecordsDialog: () => null,
}));

const renewingCertificate: SSLCertificateDetails = {
  certificateXref: "cert-629478390362668",
  domain: "app.example.org",
  status: "RENEWING",
  userDomainCertId: "101",
  deploymentCredentialXrefs: ["deploy-1"],
  validFrom: "2026-01-01T00:00:00Z",
  validTo: "2026-12-31T00:00:00Z",
};

const renewalSuccessCertificate: SSLCertificateDetails = {
  ...renewingCertificate,
  certificateXref: "cert-629275318339601",
  status: "RENEW_SUCCESS",
};

describe("CertificateDetails lifecycle actions", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUseAuth.mockReturnValue({
      isLoading: false,
      isSuperAdmin: false,
      user: {
        authMethod: "LOCAL",
        email: "user@example.com",
        id: "user-1",
        organizationId: "org-1",
        organizationName: "Org",
        permissions: ["*"],
        roles: ["USER"],
      },
    });
    mockUseIsFeatureEnabled.mockReturnValue(true);
  });

  it("shows deployment and automation actions for a current renewing certificate", async () => {
    const user = userEvent.setup();

    render(<CertificateDetails certificate={renewingCertificate} />);

    const deployButton = screen.getByRole("button", { name: "Deploy" });
    expect(deployButton).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Manage automation" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Renew" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Revoke" }),
    ).not.toBeInTheDocument();

    await user.click(deployButton);

    expect(await screen.findByTestId("deploy-dialog")).toHaveTextContent(
      "cert-629478390362668",
    );
  });

  it("offers no automation while certificate renewal is off", () => {
    mockUseIsFeatureEnabled.mockImplementation(
      (key: string) => key !== "CERTIFICATE_RENEWAL",
    );

    render(<CertificateDetails certificate={renewingCertificate} />);

    expect(
      screen.queryByRole("button", { name: "Manage automation" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Enable automation" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deploy" })).toBeInTheDocument();
  });

  it("offers request-again and no renew or deploy for a customer-held key", () => {
    render(
      <CertificateDetails
        certificate={{
          ...renewingCertificate,
          status: "ACTIVE",
          keyCustody: "CUSTOMER_HELD",
        }}
      />,
    );

    expect(screen.getByRole("link", { name: /Request again/ })).toHaveAttribute(
      "href",
      "/cert-manager/add?from=cert-629478390362668",
    );
    expect(
      screen.queryByRole("button", { name: "Renew" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Deploy" }),
    ).not.toBeInTheDocument();
  });

  it("offers no website-monitoring hand-off: that product is not part of CertPing", () => {
    render(
      <CertificateDetails
        certificate={{ ...renewingCertificate, status: "ACTIVE" }}
      />,
    );

    expect(screen.queryByRole("link", { name: /^Monitor /i })).toBeNull();
  });

  it("does not expose certificate actions for a renewal-success history record", () => {
    render(<CertificateDetails certificate={renewalSuccessCertificate} />);

    expect(
      screen.queryByRole("button", { name: "Renew" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Deploy" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Revoke" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Manage automation" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Valid Jan 1, 2026 to Dec 31, 2026/)).toBeVisible();
  });

  it("labels the certificate status in sentence case", () => {
    render(
      <CertificateDetails
        certificate={{ ...renewingCertificate, status: "AWAITING_DNS" }}
      />,
    );

    expect(
      screen.getByRole("heading", { level: 1, name: "app.example.org" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Awaiting DNS records")).toBeInTheDocument();
    expect(screen.queryByText("AWAITING_DNS")).not.toBeInTheDocument();
  });
});
