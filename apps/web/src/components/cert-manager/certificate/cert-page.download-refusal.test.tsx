// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { toast } from "sonner";

import { CertificateDetails } from "@/components/cert-manager/certificate/cert-page";
import { invalidateCertificateQueries } from "@/hooks/query-invalidation";
import { exportCertificate } from "@/lib/backend/certificate-export";
import { CertificateExportError } from "@/lib/cert-manager/certificate-export-errors";
import type { SSLCertificateDetails } from "@/types/ssl";

let mockPermissions = ["certificate:read"];

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

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: () => true,
  useIsOrgFeatureEnabled: () => true,
}));

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
jest.mock("@/lib/backend/certificate-export", () => ({
  exportCertificate: jest.fn(),
}));
jest.mock("@/hooks/query-invalidation", () => ({
  invalidateCertificateQueries: jest.fn(() => Promise.resolve()),
}));
jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

const mockedExport = exportCertificate as jest.MockedFunction<
  typeof exportCertificate
>;

const certificate: SSLCertificateDetails = {
  certificateXref: "cert-1",
  domain: "example.com",
  status: "ACTIVE",
  caProvider: "LETS_ENCRYPT",
  export: { available: true, reason: null, formats: ["FULLCHAIN_PEM"] },
};
const withdrawn: SSLCertificateDetails = {
  ...certificate,
  export: { available: false, reason: "NO_MATERIAL", formats: [] },
};

const MATERIAL_GONE =
  "CertPing no longer holds the files for this certificate.";

function renderDetails(details: SSLCertificateDetails) {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false } },
  });
  const wrap = (next: SSLCertificateDetails) => (
    <QueryClientProvider client={queryClient}>
      <CertificateDetails certificate={next} />
    </QueryClientProvider>
  );
  const view = render(wrap(details));
  return {
    user: userEvent.setup(),
    showRefetched: (next: SSLCertificateDetails) => view.rerender(wrap(next)),
  };
}

const pageDownload = () => screen.queryByRole("button", { name: "Download" });

describe("CertificateDetails download refusal (real dialog)", () => {
  it("keeps the dialog and its inline 410 after the refetch hides Download", async () => {
    mockedExport.mockRejectedValue(
      new CertificateExportError({
        status: 410,
        format: "FULLCHAIN_PEM",
        code: "CERT_MATERIAL_GONE",
        reason: null,
        retryAfterSeconds: null,
        reference: undefined,
      }),
    );
    const { user, showRefetched } = renderDetails(certificate);

    await user.click(screen.getByRole("button", { name: "Download" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Download certificate",
    });
    await user.click(within(dialog).getByRole("button", { name: "Download" }));

    await waitFor(() =>
      expect(within(dialog).getByRole("alert")).toHaveTextContent(
        MATERIAL_GONE,
      ),
    );
    expect(invalidateCertificateQueries).toHaveBeenCalled();
    expect(toast.error).not.toHaveBeenCalled();

    showRefetched(withdrawn);
    expect(
      screen.getByRole("dialog", { name: "Download certificate" }),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole("alert")).toHaveTextContent(MATERIAL_GONE);

    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(pageDownload()).not.toBeInTheDocument();

    showRefetched(certificate);
    expect(pageDownload()).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("CertificateDetails download formats by permission (real dialog)", () => {
  const offeringEveryFormat: SSLCertificateDetails = {
    ...certificate,
    export: {
      available: true,
      reason: null,
      formats: [
        "FULLCHAIN_PEM",
        "CERTIFICATE_PEM",
        "PRIVATE_KEY_PEM",
        "PKCS12",
      ],
    },
  };

  afterEach(() => {
    mockPermissions = ["certificate:read"];
  });

  const offeredFormats = async () => {
    const { user } = renderDetails(offeringEveryFormat);
    await user.click(screen.getByRole("button", { name: "Download" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Download certificate",
    });
    return within(dialog)
      .getAllByRole("radio")
      .map((radio) => radio.getAttribute("value"));
  };

  it("offers a viewer only the PEM certificate formats", async () => {
    expect(await offeredFormats()).toEqual([
      "FULLCHAIN_PEM",
      "CERTIFICATE_PEM",
    ]);
  });

  it("offers a certificate:deploy holder all four formats", async () => {
    mockPermissions = ["certificate:read", "certificate:deploy"];

    expect(await offeredFormats()).toEqual([
      "FULLCHAIN_PEM",
      "CERTIFICATE_PEM",
      "PRIVATE_KEY_PEM",
      "PKCS12",
    ]);
  });
});
