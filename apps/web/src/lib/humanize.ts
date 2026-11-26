// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

const ACRONYMS = new Set([
  "api",
  "dns",
  "ssl",
  "tls",
  "acme",
  "csr",
  "ip",
  "sso",
  "pqc",
  "ca",
]);

export function humanizeEnum(value: string | null | undefined): string {
  if (!value) return "";
  return value
    .toLowerCase()
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((word, index) =>
      ACRONYMS.has(word)
        ? word.toUpperCase()
        : index === 0
          ? word.charAt(0).toUpperCase() + word.slice(1)
          : word,
    )
    .join(" ");
}
