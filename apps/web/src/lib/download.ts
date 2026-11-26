// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * How long the object URL outlives the click. Some browsers (Firefox, older
 * Safari) start reading the blob only after `click()` returns, so revoking at
 * once can cancel the download.
 */
export const OBJECT_URL_REVOKE_DELAY_MS = 1000;

/** Saves a blob through a temporary link; the object URL is always revoked. */
export function saveBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  try {
    anchor.click();
  } finally {
    anchor.remove();
    window.setTimeout(
      () => URL.revokeObjectURL(url),
      OBJECT_URL_REVOKE_DELAY_MS,
    );
  }
}
