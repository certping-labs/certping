// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

// Hostname helpers for certificate links and query parameters.

const HOSTNAME =
  /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})+$/;

export function canonicalDomain(value: string | null | undefined): string {
  return (value ?? "").trim().toLowerCase().replace(/\.$/, "");
}

export function readDomainParam(
  value: string | null | undefined,
): string | undefined {
  const domain = canonicalDomain(value);
  return HOSTNAME.test(domain) ? domain : undefined;
}
