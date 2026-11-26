// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { KeyCustody } from "@/types/ssl";

/** The custody the backend names; absent or unknown means the platform holds the key, as it always did. */
export function parseKeyCustody(value: unknown): KeyCustody | undefined {
  return value === "CUSTOMER_HELD" || value === "PLATFORM_HELD"
    ? value
    : undefined;
}

export function isCustomerHeldKey(certificate: {
  keyCustody?: KeyCustody;
}): boolean {
  return certificate.keyCustody === "CUSTOMER_HELD";
}

/** A customer-held certificate is not renewed by CertPing; the customer requests a new one. */
export function requestAgainHref(certificateXref: string): string {
  return `/cert-manager/add?from=${encodeURIComponent(certificateXref)}`;
}
