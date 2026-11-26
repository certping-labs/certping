// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import dynamic from "next/dynamic";

import type { DownloadCertificateDialogProps } from "./download-certificate-dialog";

const loadDownloadCertificateDialog = () =>
  import("./download-certificate-dialog").then(
    (module) => module.DownloadCertificateDialog,
  );

/**
 * The download dialog loads on first use, and with it the form, the export
 * hook, the export adapter, its error mapping and file naming. The certificate
 * pages import only this wrapper, `useCanDownloadCertificates` and the
 * availability parser, so none of that ships with them.
 */
export const LazyDownloadCertificateDialog =
  dynamic<DownloadCertificateDialogProps>(loadDownloadCertificateDialog, {
    ssr: false,
  });

/** Starts fetching the dialog's code, e.g. when a Download action is hovered. */
export function preloadDownloadCertificateDialog(): void {
  void loadDownloadCertificateDialog();
}
