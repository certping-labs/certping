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
import { resetKeyRefusals } from "@/lib/cert-manager/certificate-export-key-refusals";
import type {
  CertificateExportFormat,
  ExportUnavailableReason,
} from "@/types/certificate-export";

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

const FEATURE_OFF =
  "Certificate download isn't available. Ask your CertPing administrator.";

const failure = (
  status: number | null,
  {
    format = "FULLCHAIN_PEM",
    reason = null,
    retryAfterSeconds = null,
    reference,
  }: {
    format?: CertificateExportFormat;
    reason?: ExportUnavailableReason | null;
    retryAfterSeconds?: number | null;
    reference?: string;
  } = {},
) =>
  new CertificateExportError({
    status,
    format,
    code: null,
    reason,
    retryAfterSeconds,
    reference,
  });

function renderDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false } },
  });
  const user = userEvent.setup();
  const wrap = (isOpen: boolean) => (
    <QueryClientProvider client={queryClient}>
      {isOpen ? (
        <DownloadCertificateDialog
          target={{ certificateXref: "cert-1", domain: "example.com" }}
          canDownloadPrivateKey
          onClose={() => undefined}
        />
      ) : null}
    </QueryClientProvider>
  );
  const view = render(wrap(true));
  return { user, view, hideDialog: () => view.rerender(wrap(false)) };
}

const dialog = () =>
  screen.getByRole("dialog", { name: "Download certificate" });
const downloadButton = () =>
  within(dialog()).getByRole("button", { name: "Download" });

/** A pending export the test settles by hand. */
function deferExport() {
  let rejectExport: (error: unknown) => void = () => undefined;
  mockedExport.mockReturnValue(
    new Promise((_resolve, reject) => {
      rejectExport = reject;
    }),
  );
  return (error: unknown) => rejectExport(error);
}

describe("DownloadCertificateDialog failures (real export hook)", () => {
  afterEach(() => resetKeyRefusals());

  it.each<[string, CertificateExportError]>([
    ["400", failure(400)],
    ["403", failure(403)],
    ["404", failure(404)],
    ["409 NOT_ACTIVE", failure(409, { reason: "NOT_ACTIVE" })],
    ["409 with no reason", failure(409)],
    ["410", failure(410)],
    ["429 with Retry-After", failure(429, { retryAfterSeconds: 120 })],
    ["429 without Retry-After", failure(429)],
    ["502", failure(502, { reference: "srv-1" })],
    ["503 for a PFX", failure(503, { format: "PKCS12", reference: "srv-2" })],
    ["503 for a PEM", failure(503, { reference: "srv-3" })],
    ["500", failure(500)],
    ["an unreachable server", failure(null)],
  ])("shows a %s inline while the dialog is open", async (_label, error) => {
    mockedExport.mockRejectedValue(error);
    const { user } = renderDialog();

    await user.click(downloadButton());

    await waitFor(() =>
      expect(within(dialog()).getByRole("alert")).toHaveTextContent(
        error.message,
      ),
    );
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("toasts a 423 when the dialog unmounts before the request settles", async () => {
    const settle = deferExport();
    const { user, hideDialog } = renderDialog();

    await user.click(downloadButton());
    await waitFor(() => expect(mockedExport).toHaveBeenCalled());
    hideDialog();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    settle(failure(423));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(FEATURE_OFF, {
        id: "certificate-export",
      }),
    );
  });

  it("toasts a 423 even while the dialog is still mounted, then unmounts", async () => {
    const settle = deferExport();
    const { user, hideDialog } = renderDialog();

    await user.click(downloadButton());
    settle(failure(423));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(FEATURE_OFF, {
        id: "certificate-export",
      }),
    );
    expect(within(dialog()).getByRole("alert")).toBeEmptyDOMElement();
    hideDialog();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(toast.error).toHaveBeenCalledTimes(1);
  });

  it("toasts any failure that settles after the dialog is gone", async () => {
    const settle = deferExport();
    const { user, hideDialog } = renderDialog();

    await user.click(downloadButton());
    await waitFor(() => expect(mockedExport).toHaveBeenCalled());
    hideDialog();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    settle(failure(410));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "CertPing no longer holds the files for this certificate.",
        { id: "certificate-export" },
      ),
    );
  });

  it("drops the key formats after a key-held-externally refusal, for the session", async () => {
    mockedExport.mockRejectedValue(
      failure(409, { format: "PKCS12", reason: "KEY_HELD_EXTERNALLY" }),
    );
    const { user, view } = renderDialog();
    await user.click(screen.getByRole("radio", { name: /PFX \/ PKCS#12/ }));
    await user.type(screen.getByLabelText("File password"), "long enough");
    await user.type(screen.getByLabelText("Confirm password"), "long enough");

    await user.click(downloadButton());

    await waitFor(() =>
      expect(within(dialog()).getByRole("alert")).toHaveTextContent(
        "The private key for this certificate is held outside CertPing",
      ),
    );
    const formats = () =>
      screen.getAllByRole("radio").map((radio) => radio.getAttribute("value"));
    expect(formats()).toEqual([
      "FULLCHAIN_PEM",
      "CERTIFICATE_PEM",
      "CERTIFICATE_DER",
      "PKCS7",
    ]);
    expect(screen.getByRole("radio", { name: /Full chain/ })).toBeChecked();
    expect(screen.queryByLabelText("File password")).toBeNull();

    view.unmount();
    renderDialog();
    expect(formats()).toEqual([
      "FULLCHAIN_PEM",
      "CERTIFICATE_PEM",
      "CERTIFICATE_DER",
      "PKCS7",
    ]);
  });
});
