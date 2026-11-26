// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export type SignedOutReason = "account-disabled" | "organization-suspended";

export const SIGNED_OUT_REASON_PARAM = "signedOut";

const SIGNED_OUT_REASONS: ReadonlySet<string> = new Set<SignedOutReason>([
  "account-disabled",
  "organization-suspended",
]);

export function parseSignedOutReason(value: unknown): SignedOutReason | null {
  return typeof value === "string" && SIGNED_OUT_REASONS.has(value)
    ? (value as SignedOutReason)
    : null;
}

export function getLoginPath(reason?: SignedOutReason): string {
  return reason ? `/login?${SIGNED_OUT_REASON_PARAM}=${reason}` : "/login";
}
