// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CertDetailss } from "@/components/cert-manager/certificate/cert-details";
import type { SSLCertificateDetails } from "@/types/ssl";

let mockCanCreate = true;
let mockIssuanceEnabled = true;
let mockManualIssuanceEnabled = true;
let mockCredentialsEnabled = true;
const mockUseCredentials = jest.fn();
const mockValidateDns = {
  mutate: jest.fn(),
  isPending: false,
  isError: false,
  error: null as unknown,
};

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) =>
    key === "CERTIFICATE_ISSUANCE"
      ? mockIssuanceEnabled
      : key === "CERTIFICATE_MANUAL_ISSUANCE"
        ? mockManualIssuanceEnabled
        : key === "CREDENTIALS_MANAGEMENT"
          ? mockCredentialsEnabled
          : true,
  useIsOrgFeatureEnabled: (key: string) =>
    key === "CERTIFICATE_ISSUANCE"
      ? mockIssuanceEnabled
      : key === "CERTIFICATE_MANUAL_ISSUANCE"
        ? mockManualIssuanceEnabled
        : key === "CREDENTIALS_MANAGEMENT"
          ? mockCredentialsEnabled
          : true,
}));

jest.mock("@/lib/auth-ui-mode", () => ({
  isEnterpriseAppMode: () => true,
}));

jest.mock("@/hooks/ssl", () => ({
  useCompleteDnsChallenge: () => mockValidateDns,
}));

jest.mock("@/hooks/credentials", () => ({
  useCredentials: (options: { enabled?: boolean }) => {
    mockUseCredentials(options);
    return { data: [], isLoading: false, isFetching: false };
  },
}));
jest.mock("@/lib/authz", () => ({
  ...jest.requireActual("@/lib/authz"),
  canCreateCertificates: () => mockCanCreate,
}));
jest.mock("@/stores/auth-store", () => ({
  useAuthStore: <T,>(select: (state: { user: null }) => T) =>
    select({ user: null }),
}));
jest.mock("@/components/cert-manager/credential-details-dialog", () => ({
  CredentialDetailsDialog: () => null,
}));
jest.mock("@/components/support/support-reference-link", () => ({
  SupportReferenceLink: () => null,
}));

const failed = {
  certificateXref: "cert-failed-1",
  domain: "shop.acme.com",
  status: "FAILED",
  dnsConfigXref: { "acme.com": "dns-1" },
  userMessage: "DNS validation timed out.",
  lastErrorAt: "2026-09-30T10:00:00Z",
} as unknown as SSLCertificateDetails;

const manualFailed = {
  ...failed,
  dnsConfigXref: {},
} as SSLCertificateDetails;

describe("CertDetailss", () => {
  beforeEach(() => {
    mockCanCreate = true;
    mockIssuanceEnabled = true;
    mockManualIssuanceEnabled = true;
    mockCredentialsEnabled = true;
    mockUseCredentials.mockReset();
    mockValidateDns.mutate.mockReset();
    mockValidateDns.isPending = false;
    mockValidateDns.isError = false;
    mockValidateDns.error = null;
  });

  it("leads a failed certificate with the reason and a way to request it again", () => {
    render(<CertDetailss certificate={failed} />);

    const banner = screen.getByRole("region", { name: "Issuance failed" });
    expect(banner).toHaveTextContent("This certificate failed to issue");
    expect(banner).toHaveTextContent("DNS validation timed out.");
    expect(banner).toHaveTextContent("shop.acme.com is not covered");
    expect(
      screen.getByRole("link", { name: "Request it again" }),
    ).toHaveAttribute(
      "href",
      "/cert-manager/add?from=cert-failed-1&domain=shop.acme.com",
    );
    expect(
      screen.queryByRole("button", { name: "Check DNS records again" }),
    ).not.toBeInTheDocument();
  });

  it("leads a failed manual certificate with a DNS re-check before a new request", async () => {
    const user = userEvent.setup();
    render(<CertDetailss certificate={manualFailed} />);

    const check = screen.getByRole("button", {
      name: "Check DNS records again",
    });
    const requestAgain = screen.getByRole("link", { name: "Request it again" });
    expect(
      check.compareDocumentPosition(requestAgain) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(check).toHaveAttribute("data-variant", "default");
    expect(requestAgain).toHaveAttribute("data-variant", "outline");

    await user.click(check);
    expect(mockValidateDns.mutate).toHaveBeenCalledWith({
      certificateXref: "cert-failed-1",
    });
  });

  it("shows the server's reason when the DNS re-check is refused", () => {
    mockValidateDns.isError = true;
    mockValidateDns.error = new Error(
      "Certificate is not awaiting DNS validation.",
    );
    render(<CertDetailss certificate={manualFailed} />);

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Certificate is not awaiting DNS validation.",
    );
  });

  it("offers no DNS re-check while manual issuance is switched off", () => {
    mockManualIssuanceEnabled = false;
    render(<CertDetailss certificate={manualFailed} />);

    expect(
      screen.queryByRole("button", { name: "Check DNS records again" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Request it again" }),
    ).toHaveAttribute("data-variant", "default");
  });

  it("shows the certificate secret handle the backend returns", () => {
    render(
      <CertDetailss
        certificate={{
          ...failed,
          status: "ACTIVE",
          certSecretHandle: "kv/certs/shop-acme",
        }}
      />,
    );

    expect(screen.getByText("kv/certs/shop-acme")).toBeInTheDocument();
    expect(screen.getAllByText("Active").length).toBeGreaterThan(0);
  });

  it("hides the retry while certificate issuance is switched off", () => {
    mockIssuanceEnabled = false;
    render(<CertDetailss certificate={failed} />);

    expect(
      screen.queryByRole("link", { name: "Request it again" }),
    ).not.toBeInTheDocument();
  });

  it("explains the failure without a retry for someone who cannot issue", () => {
    mockCanCreate = false;
    render(<CertDetailss certificate={failed} />);

    expect(
      screen.queryByRole("link", { name: "Request it again" }),
    ).not.toBeInTheDocument();
  });

  it("shows no failure banner for a working certificate", () => {
    render(
      <CertDetailss
        certificate={{ ...failed, status: "ACTIVE", userMessage: undefined }}
      />,
    );

    expect(
      screen.queryByRole("region", { name: "Issuance failed" }),
    ).not.toBeInTheDocument();
  });

  it("shows credential references only while credential management is on", () => {
    const { unmount } = render(<CertDetailss certificate={failed} />);
    expect(screen.getByText("Credentials")).toBeInTheDocument();
    expect(mockUseCredentials).toHaveBeenLastCalledWith({ enabled: true });
    unmount();

    mockCredentialsEnabled = false;
    render(<CertDetailss certificate={failed} />);

    expect(screen.queryByText("Credentials")).not.toBeInTheDocument();
    expect(mockUseCredentials).toHaveBeenLastCalledWith({ enabled: false });
  });
});
