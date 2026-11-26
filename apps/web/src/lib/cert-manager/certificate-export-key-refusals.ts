// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Certificates whose export was refused with `KEY_HELD_EXTERNALLY` in this
 * browser session. Their download dialog then offers only the formats without
 * the private key, until the backend reports that eligibility itself.
 *
 * <p>Held in memory only, never in web storage: it is a hint, not a secret, but
 * it should not outlive the tab or leak across users of the same browser.
 */
const MAX_REMEMBERED_REFUSALS = 500;

const refusedCertificateXrefs = new Set<string>();
const listeners = new Set<() => void>();

const notifyListeners = () => {
  listeners.forEach((listener) => listener());
};

/** Records that the backend refused this certificate's private key. */
export function rememberKeyHeldExternally(certificateXref: string): void {
  if (refusedCertificateXrefs.has(certificateXref)) {
    return;
  }
  // Bounded so a long session cannot grow it without limit; Sets iterate in
  // insertion order, so the first entry is the oldest.
  if (refusedCertificateXrefs.size >= MAX_REMEMBERED_REFUSALS) {
    const oldest = refusedCertificateXrefs.values().next().value;
    if (oldest !== undefined) {
      refusedCertificateXrefs.delete(oldest);
    }
  }
  refusedCertificateXrefs.add(certificateXref);
  notifyListeners();
}

/** True when this session saw the backend refuse this certificate's private key. */
export function isKeyHeldExternally(certificateXref: string): boolean {
  return refusedCertificateXrefs.has(certificateXref);
}

/** Subscribes to new refusals; returns the unsubscribe function. */
export function subscribeToKeyRefusals(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Forgets every refusal. For tests. */
export function resetKeyRefusals(): void {
  refusedCertificateXrefs.clear();
  notifyListeners();
}
