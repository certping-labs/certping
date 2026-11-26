// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { toast } from "sonner";

import { DownloadCertificateDialog } from "@/components/cert-manager/certificate-download/download-certificate-dialog";
import { exportCertificate } from "@/lib/backend/certificate-export";
import { CertificateExportError } from "@/lib/cert-manager/certificate-export-errors";
import type { CertificateExportFormat } from "@/types/certificate-export";

jest.mock("@/lib/backend/certificate-export", () => ({
  exportCertificate: jest.fn(),
}));
jest.mock("@/hooks/query-invalidation", () => ({
  invalidateCertificateQueries: jest.fn(() => Promise.resolve()),
}));
jest.mock("@/lib/download", () => ({ saveBlob: jest.fn() }));
jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

const mockedExport = exportCertificate as jest.MockedFunction<
  typeof exportCertificate
>;

const KEY_FREE_FORMATS = [
  "FULLCHAIN_PEM",
  "CERTIFICATE_PEM",
  "CERTIFICATE_DER",
  "PKCS7",
];
const ALL_FORMATS = [...KEY_FREE_FORMATS, "PRIVATE_KEY_PEM", "PKCS12"];
const KEY_NOT_PERMITTED =
  "You can download the certificate and chain, but not the private key.";

function renderDialog(
  canDownloadPrivateKey: boolean,
  formats?: CertificateExportFormat[],
  keyCustody?: "PLATFORM_HELD" | "CUSTOMER_HELD",
) {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <DownloadCertificateDialog
        target={{
          certificateXref: "cert-1",
          domain: "example.com",
          formats,
          keyCustody,
        }}
        canDownloadPrivateKey={canDownloadPrivateKey}
        onClose={() => undefined}
      />
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

const offeredFormats = () =>
  screen.getAllByRole("radio").map((radio) => radio.getAttribute("value"));
const dialog = () =>
  screen.getByRole("dialog", { name: "Download certificate" });

describe("DownloadCertificateDialog private-key permission", () => {
  it.each<[string, CertificateExportFormat[] | undefined]>([
    ["no per-certificate formats (list)", undefined],
    [
      "the backend's formats (detail)",
      ALL_FORMATS as CertificateExportFormat[],
    ],
  ])(
    "offers a viewer only the PEM certificate formats with %s",
    (_label, formats) => {
      renderDialog(false, formats);

      expect(offeredFormats()).toEqual(KEY_FREE_FORMATS);
    },
  );

  it.each<[string, CertificateExportFormat[] | undefined]>([
    ["no per-certificate formats (list)", undefined],
    [
      "the backend's formats (detail)",
      ALL_FORMATS as CertificateExportFormat[],
    ],
  ])("offers a deploy holder every format with %s", (_label, formats) => {
    renderDialog(true, formats);

    expect(offeredFormats()).toEqual(ALL_FORMATS);
  });

  it("never offers the key formats for a customer-held key, whatever the permission", () => {
    renderDialog(true, undefined, "CUSTOMER_HELD");

    expect(offeredFormats()).toEqual(KEY_FREE_FORMATS);
    expect(screen.queryByLabelText("File password")).toBeNull();
  });

  it("drops the key formats and switches to a key-free one on EXPORT_KEY_NOT_PERMITTED", async () => {
    mockedExport.mockRejectedValue(
      new CertificateExportError({
        status: 403,
        format: "PKCS12",
        code: "EXPORT_KEY_NOT_PERMITTED",
        reason: null,
        retryAfterSeconds: null,
        reference: undefined,
      }),
    );
    const user = renderDialog(true);
    await user.click(screen.getByRole("radio", { name: /PFX \/ PKCS#12/ }));
    await user.type(screen.getByLabelText("File password"), "long enough");
    await user.type(screen.getByLabelText("Confirm password"), "long enough");

    await user.click(
      within(dialog()).getByRole("button", { name: "Download" }),
    );

    await waitFor(() =>
      expect(within(dialog()).getByRole("alert")).toHaveTextContent(
        KEY_NOT_PERMITTED,
      ),
    );
    expect(offeredFormats()).toEqual(KEY_FREE_FORMATS);
    expect(screen.getByRole("radio", { name: /Full chain/ })).toBeChecked();
    expect(screen.queryByLabelText("File password")).toBeNull();
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("keeps the key formats after a plain 403", async () => {
    mockedExport.mockRejectedValue(
      new CertificateExportError({
        status: 403,
        format: "FULLCHAIN_PEM",
        code: "ACCESS_DENIED",
        reason: null,
        retryAfterSeconds: null,
        reference: undefined,
      }),
    );
    const user = renderDialog(true);

    await user.click(
      within(dialog()).getByRole("button", { name: "Download" }),
    );

    await waitFor(() =>
      expect(within(dialog()).getByRole("alert")).toHaveTextContent(
        "You don't have permission to download this certificate.",
      ),
    );
    expect(offeredFormats()).toEqual(ALL_FORMATS);
  });
});
