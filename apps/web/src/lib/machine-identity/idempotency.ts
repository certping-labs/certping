// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Idempotency-key handling for the Machine Identity mutations that require one.
 *
 * <p>`POST /iot/certificates/{xref}/revoke` treats the key as the identity of
 * the request: replaying it with the same body returns the original operation,
 * replaying it with a different reason or note is a `409`. A retry after a
 * timeout must therefore reuse the key it already sent - minting a fresh one
 * would create a *second* revocation operation for a request that may well
 * have succeeded.
 */

/** Ties a key to the exact request body it was minted for. */
export interface PendingIdempotentRequest {
  fingerprint: string;
  key: string;
}

export function createIdempotencyKey(): string {
  if (!globalThis.crypto?.randomUUID) {
    throw new Error("Secure request identifiers are unavailable");
  }
  return globalThis.crypto.randomUUID();
}

/**
 * Reuses the pending key when the operator is retrying the same request, and
 * mints a new one when they changed something (a different reason is a
 * different request, and reusing the key there would be rejected).
 */
export function resolveIdempotencyKey(
  pending: PendingIdempotentRequest | null,
  fingerprint: string,
): string {
  return pending?.fingerprint === fingerprint
    ? pending.key
    : createIdempotencyKey();
}
