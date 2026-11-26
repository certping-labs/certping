// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useCallback, useEffect, useRef, useSyncExternalStore } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { invalidateCertificateQueries } from "@/hooks/query-invalidation";
import { exportCertificate } from "@/lib/backend/certificate-export";
import {
  toCertificateExportError,
  type CertificateExportError,
} from "@/lib/cert-manager/certificate-export-errors";
import type { ExportFileNameSource } from "@/lib/cert-manager/certificate-export-file-name";
import {
  isKeyHeldExternally,
  rememberKeyHeldExternally,
  subscribeToKeyRefusals,
} from "@/lib/cert-manager/certificate-export-key-refusals";
import { saveBlob } from "@/lib/download";
import type {
  CertificateExportFile,
  CertificateExportRequest,
} from "@/types/certificate-export";

/** One toast id, so a repeated outcome replaces the last instead of stacking. */
export const CERTIFICATE_EXPORT_TOAST_ID = "certificate-export";

export interface ExportCertificateInput {
  certificateXref: string;
  /** Names the file when the server's `Content-Disposition` is unreadable. */
  fileNameSource: ExportFileNameSource;
  request: CertificateExportRequest;
}

interface ExportCertificateCallbacks {
  onSuccess?: (file: CertificateExportFile) => void;
  onSettled?: () => void;
}

/** Shows an export failure inside the UI that started the download. */
export type InlineExportErrorHandler = (error: CertificateExportError) => void;

interface UseExportCertificateOptions {
  /**
   * Shows failures inline while the caller is mounted; pass a stable function.
   * Without one, or once the caller has unmounted, failures become a toast.
   */
  onInlineError?: InlineExportErrorHandler;
}

/**
 * Picks where a failure is shown. A 423 always toasts: the API client's
 * interceptor has just switched the feature off, which unmounts the dialog
 * before or after this runs, so an inline message could vanish unseen.
 */
function reportExportError(
  error: CertificateExportError,
  showInline: InlineExportErrorHandler | null,
): void {
  if (showInline && !error.isFeatureLocked) {
    showInline(error);
    return;
  }
  toast.error(error.message, { id: CERTIFICATE_EXPORT_TOAST_ID });
}

/**
 * Exports a certificate and saves the file. Failures show inline in the
 * dialog while it is mounted and as a toast otherwise; a refusal that can
 * change availability refetches the certificate, and a key-held-externally
 * refusal is remembered for the session. A 423 needs nothing more here: the
 * API client's interceptor already resets and refetches the feature flags.
 *
 * <p>The mutation is reset once it settles and is never cached (`gcTime: 0`),
 * so the PFX password does not outlive the request in React Query's state.
 */
export function useExportCertificate({
  onInlineError,
}: UseExportCertificateOptions = {}) {
  const queryClient = useQueryClient();
  // Read when the request settles, which may be after the dialog unmounted;
  // the cleanup clears it so a late failure falls back to a toast.
  const inlineErrorHandlerRef = useRef<InlineExportErrorHandler | null>(null);

  useEffect(() => {
    inlineErrorHandlerRef.current = onInlineError ?? null;
    return () => {
      inlineErrorHandlerRef.current = null;
    };
  }, [onInlineError]);

  const { mutate, reset, isPending } = useMutation({
    mutationFn: ({
      certificateXref,
      fileNameSource,
      request,
    }: ExportCertificateInput) =>
      exportCertificate(certificateXref, request, fileNameSource),
    gcTime: 0,
    onSuccess: ({ blob, fileName }) => {
      saveBlob(blob, fileName);
      toast.success(`Downloaded ${fileName}`, {
        id: CERTIFICATE_EXPORT_TOAST_ID,
      });
    },
    onError: (error, { certificateXref, request }) => {
      const exportError = toCertificateExportError(error, request.format);
      if (exportError.isKeyHeldExternally) {
        rememberKeyHeldExternally(certificateXref);
      }
      if (exportError.changesAvailability) {
        void invalidateCertificateQueries(queryClient);
      }
      reportExportError(exportError, inlineErrorHandlerRef.current);
    },
  });

  const exportAndSave = useCallback(
    (input: ExportCertificateInput, callbacks?: ExportCertificateCallbacks) => {
      mutate(input, {
        onSuccess: callbacks?.onSuccess,
        onSettled: () => {
          reset();
          callbacks?.onSettled?.();
        },
      });
    },
    [mutate, reset],
  );

  return { exportAndSave, isPending };
}

const keyNotRefusedOnServer = () => false;

/**
 * True once this session saw the backend refuse the certificate's private
 * key, so the dialog offers only the formats without it.
 */
export function useIsKeyHeldExternally(certificateXref: string): boolean {
  return useSyncExternalStore(
    subscribeToKeyRefusals,
    () => isKeyHeldExternally(certificateXref),
    keyNotRefusedOnServer,
  );
}
