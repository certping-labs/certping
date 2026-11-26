// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { DownloadCertificateDialog } from "@/components/cert-manager/certificate-download/download-certificate-dialog";
import type {
  ExportCertificateInput,
  InlineExportErrorHandler,
} from "@/hooks/certificate-export";
import { CertificateExportError } from "@/lib/cert-manager/certificate-export-errors";
import type { CertificateDownloadTarget } from "@/types/certificate-export";

interface Callbacks {
  onSuccess?: () => void;
  onSettled?: () => void;
}

const mockExportAndSave = jest.fn<void, [ExportCertificateInput, Callbacks?]>();
let mockIsPending = false;
let mockIsKeyRefused = false;
let mockShowInlineError: InlineExportErrorHandler | undefined;

jest.mock("@/hooks/certificate-export", () => ({
  useExportCertificate: (options?: {
    onInlineError?: InlineExportErrorHandler;
  }) => {
    mockShowInlineError = options?.onInlineError;
    return { exportAndSave: mockExportAndSave, isPending: mockIsPending };
  },
  useIsKeyHeldExternally: () => mockIsKeyRefused,
}));

const target: CertificateDownloadTarget = {
  certificateXref: "cert-1",
  domain: "example.com",
};

const PRIVATE_KEY_NOTE =
  "Contains the private key. Store it securely and don't share it.";

function renderDialog(overrides: Partial<CertificateDownloadTarget> = {}) {
  const onClose = jest.fn();
  const user = userEvent.setup();
  render(
    <DownloadCertificateDialog
      target={{ ...target, ...overrides }}
      canDownloadPrivateKey
      onClose={onClose}
    />,
  );
  return { onClose, user };
}

const downloadButton = () => screen.getByRole("button", { name: "Download" });
const passwordInput = () => screen.getByLabelText("File password");
const confirmInput = () => screen.getByLabelText("Confirm password");

describe("DownloadCertificateDialog", () => {
  beforeEach(() => {
    mockIsPending = false;
    mockIsKeyRefused = false;
    mockShowInlineError = undefined;
  });

  it("preselects the recommended full chain and downloads it without a password", async () => {
    const { user } = renderDialog();

    expect(
      screen.getByRole("dialog", { name: "Download certificate" }),
    ).toHaveTextContent("example.com");
    expect(
      screen.getByRole("radio", { name: /Full chain \(PEM\)/ }),
    ).toBeChecked();
    expect(screen.getByText("Recommended")).toBeInTheDocument();
    expect(screen.queryByText(PRIVATE_KEY_NOTE)).not.toBeInTheDocument();
    expect(screen.queryByLabelText("File password")).not.toBeInTheDocument();

    await waitFor(() => expect(downloadButton()).toBeEnabled());
    await user.click(downloadButton());

    await waitFor(() => expect(mockExportAndSave).toHaveBeenCalled());
    expect(mockExportAndSave.mock.calls[0][0]).toEqual({
      certificateXref: "cert-1",
      fileNameSource: { domain: "example.com", isWildcard: false },
      request: { format: "FULLCHAIN_PEM" },
    });
  });

  it("offers only the formats the certificate supports", () => {
    renderDialog({ formats: ["CERTIFICATE_PEM", "PRIVATE_KEY_PEM"] });

    const radios = screen.getAllByRole("radio");
    expect(radios).toHaveLength(2);
    expect(
      screen.getByRole("radio", { name: /Certificate only/ }),
    ).toBeChecked();
  });

  it("notes that the private key is included", async () => {
    const { user } = renderDialog();

    await user.click(
      screen.getByRole("radio", { name: /Private key \(PEM\)/ }),
    );
    expect(screen.getByText(PRIVATE_KEY_NOTE)).toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: /Certificate only/ }));
    expect(screen.queryByText(PRIVATE_KEY_NOTE)).not.toBeInTheDocument();
  });

  it("validates the PFX password as the user leaves each field", async () => {
    const { user } = renderDialog();

    await user.click(screen.getByRole("radio", { name: /PFX \/ PKCS#12/ }));
    expect(screen.getByText(PRIVATE_KEY_NOTE)).toBeInTheDocument();
    expect(downloadButton()).toBeEnabled();

    await user.type(passwordInput(), "short");
    await user.tab();
    expect(
      await screen.findByText("Use at least 8 characters."),
    ).toBeInTheDocument();
    expect(passwordInput()).toHaveAttribute("aria-invalid", "true");

    await user.clear(passwordInput());
    await user.type(passwordInput(), "long enough");
    await user.type(confirmInput(), "long enougX");
    await user.tab();
    expect(
      await screen.findByText("The passwords don't match."),
    ).toBeInTheDocument();

    await user.clear(confirmInput());
    await user.type(confirmInput(), "long enough");
    await waitFor(() =>
      expect(
        screen.queryByText("The passwords don't match."),
      ).not.toBeInTheDocument(),
    );
  });

  it("validates on a keyboard submit and focuses the first invalid field", async () => {
    const { user } = renderDialog();

    await user.click(screen.getByRole("radio", { name: /PFX \/ PKCS#12/ }));
    downloadButton().focus();
    await user.keyboard("{Enter}");

    expect(
      await screen.findByText("Use at least 8 characters."),
    ).toBeInTheDocument();
    await waitFor(() => expect(passwordInput()).toHaveFocus());
    expect(mockExportAndSave).not.toHaveBeenCalled();
  });

  it("reports an over-long password instead of truncating it", async () => {
    const { user } = renderDialog();

    await user.click(screen.getByRole("radio", { name: /PFX \/ PKCS#12/ }));
    expect(passwordInput()).not.toHaveAttribute("maxlength");
    expect(confirmInput()).not.toHaveAttribute("maxlength");
    await user.click(passwordInput());
    await user.paste("a".repeat(129));
    await user.tab();

    expect(passwordInput()).toHaveValue("a".repeat(129));
    expect(
      await screen.findByText("Use 128 characters or fewer."),
    ).toBeInTheDocument();
  });

  it("sends the password and legacy choice, then clears the password fields", async () => {
    const { user, onClose } = renderDialog();

    await user.click(screen.getByRole("radio", { name: /PFX \/ PKCS#12/ }));
    await user.type(passwordInput(), "long enough");
    await user.type(confirmInput(), "long enough");
    await user.click(
      screen.getByRole("checkbox", { name: /Legacy compatibility/ }),
    );
    await user.click(downloadButton());

    await waitFor(() => expect(mockExportAndSave).toHaveBeenCalled());
    const [input, callbacks] = mockExportAndSave.mock.calls[0];
    expect(input.request).toEqual({
      format: "PKCS12",
      password: "long enough",
      legacyPkcs12: true,
    });

    callbacks?.onSettled?.();
    await waitFor(() => expect(passwordInput()).toHaveValue(""));
    expect(confirmInput()).toHaveValue("");
    expect(onClose).not.toHaveBeenCalled();

    callbacks?.onSuccess?.();
    expect(onClose).toHaveBeenCalled();
  });

  it("shows a failure inline until the user edits or retries", async () => {
    const { user } = renderDialog();
    const alert = screen.getByRole("alert");
    expect(alert).toBeEmptyDOMElement();

    act(() =>
      mockShowInlineError?.(
        new CertificateExportError({
          status: 429,
          format: "FULLCHAIN_PEM",
          code: null,
          reason: null,
          retryAfterSeconds: null,
          reference: undefined,
        }),
      ),
    );
    expect(alert).toHaveTextContent(
      "You've reached the download limit for now. Try again later.",
    );

    await user.click(downloadButton());
    expect(alert).toBeEmptyDOMElement();

    act(() =>
      mockShowInlineError?.(
        new CertificateExportError({
          status: 410,
          format: "FULLCHAIN_PEM",
          code: null,
          reason: null,
          retryAfterSeconds: null,
          reference: undefined,
        }),
      ),
    );
    expect(alert).toHaveTextContent(
      "CertPing no longer holds the files for this certificate.",
    );
    await user.click(screen.getByRole("radio", { name: /Certificate only/ }));
    expect(alert).toBeEmptyDOMElement();
  });

  it("offers only the formats without the key once the key was refused", () => {
    mockIsKeyRefused = true;
    renderDialog();

    expect(
      screen.getAllByRole("radio").map((radio) => radio.getAttribute("value")),
    ).toEqual(["FULLCHAIN_PEM", "CERTIFICATE_PEM", "CERTIFICATE_DER", "PKCS7"]);
  });

  it("drops a typed password when the user switches away from PFX", async () => {
    const { user } = renderDialog();

    await user.click(screen.getByRole("radio", { name: /PFX \/ PKCS#12/ }));
    await user.type(passwordInput(), "long enough");
    await user.click(screen.getByRole("radio", { name: /Full chain/ }));
    await user.click(screen.getByRole("radio", { name: /PFX \/ PKCS#12/ }));

    expect(passwordInput()).toHaveValue("");
  });

  it("closes from Cancel", async () => {
    const { user, onClose } = renderDialog();

    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(onClose).toHaveBeenCalled();
  });

  it("keeps the dialog and its label while a download is in flight", async () => {
    mockIsPending = true;
    const { user, onClose } = renderDialog();

    expect(downloadButton()).toBeDisabled();
    expect(downloadButton()).toHaveAttribute("aria-busy", "true");
    expect(downloadButton()).toHaveTextContent("Download");
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();

    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes on Escape when idle", async () => {
    const { user, onClose } = renderDialog();

    await user.keyboard("{Escape}");

    expect(onClose).toHaveBeenCalled();
  });
});
