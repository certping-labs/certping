// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export const PROGRESSIVE_PAGE_REQUEST_GAP_MS = 300;

/** Keeps inventory pagination sequential and gives the API a brief recovery window. */
export const waitForProgressivePageWindow = (
  signal: AbortSignal,
): Promise<void> =>
  new Promise((resolve, reject) => {
    const handleAbort = () => {
      window.clearTimeout(timeoutId);
      reject(
        signal.reason ?? new DOMException("Request aborted", "AbortError"),
      );
    };
    const handleElapsed = () => {
      signal.removeEventListener("abort", handleAbort);
      resolve();
    };
    const timeoutId = window.setTimeout(
      handleElapsed,
      PROGRESSIVE_PAGE_REQUEST_GAP_MS,
    );
    signal.addEventListener("abort", handleAbort, { once: true });
  });
