// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CertificateActions } from "@/components/cert-manager/certificate-row-actions";
import type { SSLCertificateListItem } from "@/types/ssl";

jest.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({
    children,
    onClick,
    asChild,
  }: {
    children: React.ReactNode;
    onClick?: () => void;
    asChild?: boolean;
  }) =>
    asChild ? (
      <div>{children}</div>
    ) : (
      <button type="button" onClick={onClick}>
        {children}
      </button>
    ),
}));

function renderActions(
  certificate: SSLCertificateListItem,
  overrides: {
    canDelete?: boolean;
    canManageCredentialConfig?: boolean;
    isCertRenewalEnabled?: boolean;
  } = {},
) {
  const handlers = {
    onDelete: jest.fn(),
    onRevoke: jest.fn(),
    onRenew: jest.fn(),
    onDownload: jest.fn(),
  };
  render(
    <CertificateActions
      certificate={certificate}
      canDelete={overrides.canDelete ?? true}
      canDeploy
      canManageCredentialConfig={overrides.canManageCredentialConfig ?? false}
      canRenew
      canRevoke
      isCertRenewalEnabled={overrides.isCertRenewalEnabled ?? true}
      isCertRevocationEnabled
      onOpenManualDns={jest.fn()}
      onManageCredentialConfig={jest.fn()}
      {...handlers}
    />,
  );
  return handlers;
}

describe("CertificateActions", () => {
  it("offers delete for a deletable row that has a managed-domain id but no xref", async () => {
    const user = userEvent.setup();
    const certificate: SSLCertificateListItem = {
      domain: "orphan.example.com",
      status: "FAILED",
      userDomainCertId: "7",
    };
    const { onDelete } = renderActions(certificate);

    await user.click(
      screen.getByRole("button", { name: /Delete certificate/ }),
    );
    expect(onDelete).toHaveBeenCalledWith(certificate);
  });

  it("offers automation only while certificate renewal is on", () => {
    const certificate: SSLCertificateListItem = {
      certificateXref: "cert-1",
      domain: "auto.example.com",
      status: "ACTIVE",
      userDomainCertId: "9",
    };
    renderActions(certificate, { canManageCredentialConfig: true });
    expect(screen.getByText(/automation/)).toBeInTheDocument();
  });

  it("hides automation while certificate renewal is off", () => {
    renderActions(
      {
        certificateXref: "cert-1",
        domain: "auto.example.com",
        status: "ACTIVE",
        userDomainCertId: "9",
      },
      { canManageCredentialConfig: true, isCertRenewalEnabled: false },
    );
    expect(screen.queryByText(/automation/)).not.toBeInTheDocument();
  });

  it("hides delete without the permission or the managed-domain id", () => {
    renderActions(
      { domain: "a.example.com", status: "FAILED", userDomainCertId: "7" },
      { canDelete: false },
    );
    renderActions({ domain: "b.example.com", status: "FAILED" });
    expect(
      screen.queryByRole("button", { name: /Delete certificate/ }),
    ).not.toBeInTheDocument();
  });

  it("keeps every xref action off a row without an xref", () => {
    renderActions({
      domain: "live.example.com",
      status: "ACTIVE",
      userDomainCertId: "8",
      exportAvailable: true,
    });
    expect(screen.queryByText(/Revoke certificate/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Renew certificate/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Deploy certificate/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Download$/)).not.toBeInTheDocument();
  });

  it("offers request-again instead of renew or deploy for a customer-held key", () => {
    renderActions({
      certificateXref: "xref-held",
      domain: "held.example.com",
      status: "ACTIVE",
      keyCustody: "CUSTOMER_HELD",
      validTo: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
    });

    expect(screen.getByRole("link", { name: /Request again/ })).toHaveAttribute(
      "href",
      "/cert-manager/add?from=xref-held",
    );
    expect(screen.queryByText(/Renew certificate/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Renew now/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Deploy certificate/)).not.toBeInTheDocument();
  });

  it("offers revoke on a live row that has an xref", async () => {
    const user = userEvent.setup();
    const certificate: SSLCertificateListItem = {
      certificateXref: "xref-9",
      domain: "live.example.com",
      status: "ACTIVE",
    };
    const { onRevoke } = renderActions(certificate);

    await user.click(
      screen.getByRole("button", { name: /Revoke certificate/ }),
    );
    expect(onRevoke).toHaveBeenCalledWith(certificate);
  });
});
