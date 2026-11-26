// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Generic presentation helpers shared across the Machine Identity module.
 * Domain-specific label/variant maps live next to their domain in
 * `backend-display.ts`.
 */

/**
 * Tokens that are acronyms, not words.
 *
 * <p>Sentence-casing a constant is right for `MANAGED_ENDPOINT`, but it turns
 * `SIGN_CSR` into "Sign csr" and `apiHost` into "Api host", which reads as a
 * typo in a console whose whole subject matter is acronyms. Keyed by the
 * lowercase token so both `SCEP_SERVER` and `scepServer` normalize the same
 * way.
 */
const ACRONYMS: Record<string, string> = {
  aad: "AAD",
  ad: "AD",
  api: "API",
  ca: "CA",
  cn: "CN",
  crl: "CRL",
  csr: "CSR",
  dn: "DN",
  dns: "DNS",
  ec: "EC",
  ejbca: "EJBCA",
  eku: "EKU",
  est: "EST",
  hsm: "HSM",
  http: "HTTP",
  https: "HTTPS",
  id: "ID",
  ip: "IP",
  json: "JSON",
  mdm: "MDM",
  ocsp: "OCSP",
  oid: "OID",
  os: "OS",
  pkcs: "PKCS",
  pki: "PKI",
  rsa: "RSA",
  san: "SAN",
  scep: "SCEP",
  sha: "SHA",
  ski: "SKI",
  tls: "TLS",
  upn: "UPN",
  uri: "URI",
  url: "URL",
  uuid: "UUID",
};

/** Sentence-cases a token run, restoring any token that is really an acronym. */
function toSentenceCase(words: string[]): string {
  const cased = words.map((word, index) => {
    const acronym = ACRONYMS[word];
    if (acronym) return acronym;
    if (index > 0) return word;
    return word.charAt(0).toUpperCase() + word.slice(1);
  });
  return cased.join(" ");
}

/** Turns an enum-ish constant into a readable fallback label. */
export function humanizeConstant(
  value: string | null | undefined,
  fallback = "Unknown",
): string {
  const normalized = value?.trim();
  if (!normalized) return fallback;
  return toSentenceCase(
    normalized.replaceAll("_", " ").toLowerCase().split(" "),
  );
}

/** Turns a JSON object key (`camelCase` or `snake_case`) into a readable label. */
export function humanizeKey(key: string): string {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .toLowerCase()
    .split(" ")
    .filter(Boolean);
  return words.length === 0 ? key : toSentenceCase(words);
}

/** Builds `{value, label}` option lists for filter and form selects. */
export function toSelectOptions<T extends string>(
  labels: Record<T, string>,
): { value: T; label: string }[] {
  return (Object.keys(labels) as T[]).map((value) => ({
    value,
    label: labels[value],
  }));
}

/**
 * Narrows a URL-supplied filter value to one of the API's own constants.
 *
 * <p>Filter state round-trips through the query string, so a stale bookmark or
 * a hand-edited URL can carry a value the backend's enum binder will reject
 * with a `400` - a failure a retry can never clear. Anything unrecognized is
 * dropped here instead, leaving the list unfiltered rather than broken.
 */
export function asEnumValue<T extends string>(
  value: string | null | undefined,
  allowed: Record<T, unknown>,
): T | undefined {
  return value && Object.prototype.hasOwnProperty.call(allowed, value)
    ? (value as T)
    : undefined;
}

/** `1 day` / `2 days`, so a validity of one never renders as "1 days". */
export function pluralize(count: number, singular: string, plural?: string) {
  return `${count.toLocaleString()} ${count === 1 ? singular : (plural ?? `${singular}s`)}`;
}
