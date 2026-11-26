// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CertificateDetails } from "@/components/cert-manager/certificate/cert-page";
import type { CertificateExportAvailability } from "@/types/certificate-export";
import type { SSLCertificateDetails } from "@/types/ssl";

let mockDownloadFlagOn = true;
let mockPermissions = ["certificate:read"];
const mockPreload = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn() }),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "user-1",
      organizationId: "org-1",
      roles: ["USER"],
      permissions: mockPermissions,
    },
  }),
}));

jest.mock("@/hooks/use-feature-flags", () => {
  const isOn = (key: string) =>
    key === "CERTIFICATE_DOWNLOAD" ? mockDownloadFlagOn : true;
  return { useIsFeatureEnabled: isOn, useIsOrgFeatureEnabled: isOn };
});

jest.mock("@/hooks/ssl", () => {
  const mutation = { mutate: jest.fn(), mutateAsync: jest.fn() };
  return {
    useCompleteDnsChallenge: () => mutation,
    useDeletePendingSSLCertificate: () => mutation,
    useGetTxtRecords: () => mutation,
    useRenewCertificate: () => mutation,
    useRevokeCertificate: () => mutation,
  };
});

jest.mock("@/components/cert-manager/certificate-management-dialog", () => ({
  CertificateManagementDialog: () => null,
  CertificateManagementSummaryCard: () => null,
}));
jest.mock("@/components/cert-manager/deploy-new-cert-dialog", () => ({
  DeployNewCertDialog: () => null,
}));
jest.mock("@/components/cert-manager/certificate/cert-details", () => ({
  CertDetailss: () => null,
}));
jest.mock("@/components/cert-manager/certificate/cert-deployments", () => ({
  CertDeployments: () => null,
}));
jest.mock("@/components/cert-manager/certificate/cert-history", () => ({
  CertHistory: () => null,
}));
jest.mock("@/components/cert-manager/manual-txt-records-dialog", () => ({
  ManualTxtRecordsDialog: () => null,
}));
jest.mock(
  "@/components/cert-manager/certificate-download/lazy-download-certificate-dialog",
  () => ({
    preloadDownloadCertificateDialog: () => mockPreload(),
    LazyDownloadCertificateDialog: ({
      target,
      onClose,
    }: {
      target: { domain: string; formats?: string[] };
      onClose: () => void;
    }) => (
      <div role="dialog" aria-label="Download certificate">
        {target.domain}: {target.formats?.join(",")}
        <button type="button" onClick={onClose}>
          Close download
        </button>
      </div>
    ),
  }),
);

const exportable: CertificateExportAvailability = {
  available: true,
  reason: null,
  formats: ["FULLCHAIN_PEM", "PKCS12"],
};

const certificate: SSLCertificateDetails = {
  certificateXref: "cert-1",
  domain: "example.com",
  status: "ACTIVE",
  caProvider: "LETS_ENCRYPT",
  export: exportable,
};

const queryDownload = () => screen.queryByRole("button", { name: "Download" });

describe("CertificateDetails download action", () => {
  afterEach(() => {
    mockDownloadFlagOn = true;
    mockPermissions = ["certificate:read"];
  });

  it("prompts to download a certificate issued today", () => {
    render(
      <CertificateDetails
        certificate={{ ...certificate, validFrom: new Date().toISOString() }}
      />,
    );

    expect(
      screen.getByText(/Your certificate is ready\. Download it/),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Download" })).toHaveLength(2);
  });

  it("does not prompt for a certificate issued a while ago", () => {
    render(
      <CertificateDetails
        certificate={{ ...certificate, validFrom: "2025-06-01T00:00:00Z" }}
      />,
    );

    expect(
      screen.queryByText(/Your certificate is ready/),
    ).not.toBeInTheDocument();
  });

  it("opens the download dialog for an exportable certificate", async () => {
    const user = userEvent.setup();
    render(<CertificateDetails certificate={certificate} />);

    const download = screen.getByRole("button", { name: "Download" });
    await user.hover(download);
    expect(mockPreload).toHaveBeenCalled();

    await user.click(download);
    expect(
      screen.getByRole("dialog", { name: "Download certificate" }),
    ).toHaveTextContent("example.com: FULLCHAIN_PEM,PKCS12");

    await user.click(screen.getByRole("button", { name: "Close download" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("keeps an open dialog when a refetch withdraws availability, and never reopens it", async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <CertificateDetails certificate={certificate} />,
    );
    await user.click(screen.getByRole("button", { name: "Download" }));

    rerender(
      <CertificateDetails
        certificate={{
          ...certificate,
          export: { available: false, reason: "NO_MATERIAL", formats: [] },
        }}
      />,
    );
    expect(
      screen.getByRole("dialog", { name: "Download certificate" }),
    ).toHaveTextContent("example.com: FULLCHAIN_PEM,PKCS12");
    expect(queryDownload()).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Close download" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(queryDownload()).not.toBeInTheDocument();

    rerender(<CertificateDetails certificate={certificate} />);
    expect(queryDownload()).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("does not reopen the dialog when download access returns after being lost", async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <CertificateDetails certificate={certificate} />,
    );
    const rerenderWithFlag = (on: boolean) => {
      mockDownloadFlagOn = on;
      rerender(<CertificateDetails certificate={certificate} />);
    };
    await user.click(screen.getByRole("button", { name: "Download" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    rerenderWithFlag(false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(queryDownload()).not.toBeInTheDocument();

    rerenderWithFlag(true);
    expect(queryDownload()).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Download" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    rerenderWithFlag(false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    rerenderWithFlag(true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it.each<[string, Partial<SSLCertificateDetails>]>([
    [
      "the backend says it is not exportable",
      {
        export: {
          available: false,
          reason: "NOT_PLATFORM_STORED",
          formats: [],
        },
      },
    ],
    ["the backend sends no export block", { export: undefined }],
    ["it has no xref", { certificateXref: undefined }],
  ])("hides Download when %s", (_label, overrides) => {
    render(
      <CertificateDetails certificate={{ ...certificate, ...overrides }} />,
    );
    expect(queryDownload()).not.toBeInTheDocument();
  });

  it("hides Download while the feature flag is not confirmed on", () => {
    mockDownloadFlagOn = false;
    render(<CertificateDetails certificate={certificate} />);
    expect(queryDownload()).not.toBeInTheDocument();
  });

  it("hides Download from users who cannot view certificates", () => {
    mockPermissions = ["credential:read"];
    render(<CertificateDetails certificate={certificate} />);
    expect(queryDownload()).not.toBeInTheDocument();
  });
});
