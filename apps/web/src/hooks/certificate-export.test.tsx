// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { toast } from "sonner";

import {
  CERTIFICATE_EXPORT_TOAST_ID,
  useExportCertificate,
  useIsKeyHeldExternally,
  type ExportCertificateInput,
  type InlineExportErrorHandler,
} from "@/hooks/certificate-export";
import { exportCertificate } from "@/lib/backend/certificate-export";
import { CertificateExportError } from "@/lib/cert-manager/certificate-export-errors";
import { resetKeyRefusals } from "@/lib/cert-manager/certificate-export-key-refusals";
import { saveBlob } from "@/lib/download";

jest.mock("@/lib/backend/certificate-export", () => ({
  exportCertificate: jest.fn(),
}));
jest.mock("@/lib/download", () => ({ saveBlob: jest.fn() }));
jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

const mockedExport = exportCertificate as jest.MockedFunction<
  typeof exportCertificate
>;

const PASSWORD = "s3cret-pfx-password";

const pfxInput: ExportCertificateInput = {
  certificateXref: "cert-1",
  fileNameSource: { domain: "example.com", isWildcard: false },
  request: { format: "PKCS12", password: PASSWORD, legacyPkcs12: false },
};

const exportFailure = (
  status: number,
  reason: CertificateExportError["reason"] = null,
) =>
  new CertificateExportError({
    status,
    format: "PKCS12",
    code: null,
    reason,
    retryAfterSeconds: null,
    reference: undefined,
  });

function renderExportHook(onInlineError?: InlineExportErrorHandler) {
  const queryClient = new QueryClient({
    defaultOptions: { mutations: { retry: false } },
  });
  const invalidate = jest.spyOn(queryClient, "invalidateQueries");
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  const hook = renderHook(() => useExportCertificate({ onInlineError }), {
    wrapper,
  });
  return { ...hook, queryClient, invalidate };
}

const retainsPassword = (queryClient: QueryClient): boolean =>
  queryClient
    .getMutationCache()
    .getAll()
    .some((mutation) =>
      JSON.stringify(mutation.state.variables ?? null).includes(PASSWORD),
    );

describe("useExportCertificate", () => {
  it("saves the file, confirms it, and forgets the password", async () => {
    const blob = new Blob(["pfx"]);
    mockedExport.mockResolvedValue({ blob, fileName: "example.com.pfx" });
    const onSuccess = jest.fn();
    const onSettled = jest.fn();
    const { result, queryClient } = renderExportHook();

    act(() => result.current.exportAndSave(pfxInput, { onSuccess, onSettled }));

    await waitFor(() => expect(onSettled).toHaveBeenCalled());
    expect(mockedExport).toHaveBeenCalledWith("cert-1", pfxInput.request, {
      domain: "example.com",
      isWildcard: false,
    });
    expect(saveBlob).toHaveBeenCalledWith(blob, "example.com.pfx");
    expect(toast.success).toHaveBeenCalledWith("Downloaded example.com.pfx", {
      id: CERTIFICATE_EXPORT_TOAST_ID,
    });
    expect(onSuccess).toHaveBeenCalled();
    expect(result.current.isPending).toBe(false);
    await waitFor(() => expect(retainsPassword(queryClient)).toBe(false));
  });

  it("works without callbacks", async () => {
    mockedExport.mockResolvedValue({ blob: new Blob([]), fileName: "a.pem" });
    const { result } = renderExportHook();

    act(() =>
      result.current.exportAndSave({
        ...pfxInput,
        request: { format: "CERTIFICATE_PEM" },
      }),
    );

    await waitFor(() => expect(saveBlob).toHaveBeenCalled());
  });

  it("shows the mapped message and refetches the certificate when its files are gone", async () => {
    mockedExport.mockRejectedValue(exportFailure(410));
    const onSettled = jest.fn();
    const { result, queryClient, invalidate } = renderExportHook();

    act(() => result.current.exportAndSave(pfxInput, { onSettled }));

    await waitFor(() => expect(onSettled).toHaveBeenCalled());
    expect(toast.error).toHaveBeenCalledWith(
      "CertPing no longer holds the files for this certificate.",
      { id: CERTIFICATE_EXPORT_TOAST_ID },
    );
    expect(saveBlob).not.toHaveBeenCalled();
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["ssl-cert-details"] });
    await waitFor(() => expect(retainsPassword(queryClient)).toBe(false));
  });

  it("does not refetch on a rate limit", async () => {
    mockedExport.mockRejectedValue(exportFailure(429));
    const onSettled = jest.fn();
    const { result, invalidate } = renderExportHook();

    act(() => result.current.exportAndSave(pfxInput, { onSettled }));

    await waitFor(() => expect(onSettled).toHaveBeenCalled());
    expect(toast.error).toHaveBeenCalledWith(
      expect.stringContaining("download limit for now"),
      { id: CERTIFICATE_EXPORT_TOAST_ID },
    );
    expect(invalidate).not.toHaveBeenCalled();
  });

  it("shows a failure inline, not as a toast, while a handler is registered", async () => {
    mockedExport.mockRejectedValue(exportFailure(410));
    const onInlineError = jest.fn();
    const onSettled = jest.fn();
    const { result, invalidate } = renderExportHook(onInlineError);

    act(() => result.current.exportAndSave(pfxInput, { onSettled }));

    await waitFor(() => expect(onSettled).toHaveBeenCalled());
    expect(onInlineError).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 410,
        message: "CertPing no longer holds the files for this certificate.",
      }),
    );
    expect(toast.error).not.toHaveBeenCalled();
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["ssl-cert-details"] });
  });

  it("always toasts a 423, even with an inline handler", async () => {
    mockedExport.mockRejectedValue(exportFailure(423));
    const onInlineError = jest.fn();
    const onSettled = jest.fn();
    const { result } = renderExportHook(onInlineError);

    act(() => result.current.exportAndSave(pfxInput, { onSettled }));

    await waitFor(() => expect(onSettled).toHaveBeenCalled());
    expect(toast.error).toHaveBeenCalledWith(
      "Certificate download isn't available. Ask your CertPing administrator.",
      { id: CERTIFICATE_EXPORT_TOAST_ID },
    );
    expect(onInlineError).not.toHaveBeenCalled();
  });

  it("falls back to a toast when the caller unmounted before the failure", async () => {
    let rejectExport: (error: unknown) => void = () => undefined;
    mockedExport.mockReturnValue(
      new Promise((_resolve, reject) => {
        rejectExport = reject;
      }),
    );
    const onInlineError = jest.fn();
    const { result, unmount } = renderExportHook(onInlineError);

    act(() => result.current.exportAndSave(pfxInput));
    await waitFor(() => expect(mockedExport).toHaveBeenCalled());
    unmount();
    rejectExport(exportFailure(503));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        expect.stringContaining("temporarily unavailable"),
        { id: CERTIFICATE_EXPORT_TOAST_ID },
      ),
    );
    expect(onInlineError).not.toHaveBeenCalled();
  });
});

describe("useIsKeyHeldExternally", () => {
  afterEach(() => resetKeyRefusals());

  it("remembers a key-held-externally refusal for that certificate only", async () => {
    mockedExport.mockRejectedValue(exportFailure(409, "KEY_HELD_EXTERNALLY"));
    const onSettled = jest.fn();
    const { result } = renderExportHook(jest.fn());
    const refused = renderHook(() => useIsKeyHeldExternally("cert-1"));
    const other = renderHook(() => useIsKeyHeldExternally("cert-2"));
    expect(refused.result.current).toBe(false);

    act(() => result.current.exportAndSave(pfxInput, { onSettled }));

    await waitFor(() => expect(refused.result.current).toBe(true));
    expect(other.result.current).toBe(false);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});
