// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { CertificateExportFormat } from "@/types/certificate-export";

/** Mirrors the backend's file suffixes so a fallback name matches the real one. */
const FILE_SUFFIX: Record<CertificateExportFormat, string> = {
  FULLCHAIN_PEM: "-fullchain.pem",
  CERTIFICATE_PEM: "-cert.pem",
  CERTIFICATE_DER: "-cert.der",
  PKCS7: "-chain.p7b",
  PRIVATE_KEY_PEM: "-privkey.pem",
  PKCS12: ".pfx",
};

/** The backend's `CertExportFileNames.MAX_STEM_LENGTH`. */
export const MAX_FILE_STEM_LENGTH = 100;
const MAX_HEADER_FILE_NAME_LENGTH = 128;
const DEFAULT_STEM = "certificate";
const WILDCARD_PREFIX = "*.";

// Same rules, in the same order, as the backend's `safeCommonName`. The
// character class has no `u` flag on purpose: like Java, each UTF-16 code
// unit outside the alphabet becomes one replacement character.
const UNSAFE_STEM_CHARACTER = /[^a-z0-9._-]/g;
const DOT_RUN = /\.{2,}/g;
const LEADING_SEPARATORS = /^[.-]+/;
const TRAILING_SEPARATORS = /[.-]+$/;

const UNSAFE_HEADER_CHARACTERS = /[^a-z0-9._-]+/g;
const LEADING_DOTS_OR_DASHES = /^[.-]+/;
const RFC_5987_FILE_NAME =
  /filename\*\s*=\s*(?:utf-8|iso-8859-1)'[^']*'([^;]+)/i;
const QUOTED_FILE_NAME = /filename\s*=\s*"([^"]*)"/i;
const BARE_FILE_NAME = /filename\s*=\s*([^;\s]+)/i;

/**
 * The backend's `safeCommonName`: lower case, `*` written as `_wildcard`,
 * anything outside `[a-z0-9._-]` replaced by `-`, dot runs collapsed, leading
 * and trailing dots or dashes trimmed, at most 100 characters.
 */
export function toSafeFileStem(name: string | null | undefined): string {
  if (name == null) {
    return DEFAULT_STEM;
  }
  let stem = name
    .trim()
    .toLowerCase()
    .replace(/\*/g, "_wildcard")
    .replace(UNSAFE_STEM_CHARACTER, "-")
    .replace(DOT_RUN, ".")
    .replace(LEADING_SEPARATORS, "")
    .replace(TRAILING_SEPARATORS, "");
  if (stem.length > MAX_FILE_STEM_LENGTH) {
    stem = stem.slice(0, MAX_FILE_STEM_LENGTH).replace(TRAILING_SEPARATORS, "");
  }
  return stem || DEFAULT_STEM;
}

/**
 * The stem the backend derives when the leaf has no common name: the primary
 * domain, prefixed with `*.` for a wildcard certificate. The browser never
 * sees the leaf, so this is the closest name it can rebuild.
 */
export function toDomainFileStem(
  domain: string | null | undefined,
  isWildcard: boolean,
): string {
  const trimmed = domain?.trim();
  const needsWildcardLabel =
    isWildcard && Boolean(trimmed) && !trimmed?.startsWith(WILDCARD_PREFIX);
  return toSafeFileStem(
    needsWildcardLabel ? `${WILDCARD_PREFIX}${trimmed}` : trimmed,
  );
}

/** Who the file is for, used to name it when the server's name is unreadable. */
export interface ExportFileNameSource {
  domain: string;
  isWildcard: boolean;
}

/** The name the backend would most likely have sent, for when the header is unreadable. */
export function buildFallbackExportFileName(
  source: ExportFileNameSource | undefined,
  format: CertificateExportFormat,
): string {
  const stem = toDomainFileStem(source?.domain, source?.isWildcard === true);
  return `${stem}${FILE_SUFFIX[format]}`;
}

/**
 * Makes a server-sent name safe to save: only its last path segment, reduced
 * to `[a-z0-9._-]`, with no leading dot or dash, so a header can never steer
 * the save into another directory or create a hidden file.
 */
export function sanitizeExportFileName(value: string): string {
  const lastSegment = value.split(/[\\/]/).pop() ?? "";
  return lastSegment
    .trim()
    .toLowerCase()
    .replace(UNSAFE_HEADER_CHARACTERS, "_")
    .replace(LEADING_DOTS_OR_DASHES, "")
    .slice(0, MAX_HEADER_FILE_NAME_LENGTH);
}

const decodeFileName = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

/** The file name a `Content-Disposition` header carries, sanitized; null without one. */
export function parseContentDispositionFileName(
  header: unknown,
): string | null {
  if (typeof header !== "string" || !header.trim()) {
    return null;
  }
  const extended = RFC_5987_FILE_NAME.exec(header)?.[1];
  const quoted = QUOTED_FILE_NAME.exec(header)?.[1];
  const bare = BARE_FILE_NAME.exec(header)?.[1];
  const raw = extended ? decodeFileName(extended) : (quoted ?? bare);
  const fileName = raw ? sanitizeExportFileName(raw) : "";
  return fileName || null;
}
