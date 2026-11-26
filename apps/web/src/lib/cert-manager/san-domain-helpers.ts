// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export interface SanConflict {
  domain: string;
  reason: string;
}

export interface SanNormalizationResult {
  accepted: string[];
  conflicts: SanConflict[];
}

export interface SanCredentialGroup {
  key: string;
  domains: string[];
}

const normalizeDomain = (value: string): string =>
  value.trim().toLowerCase().replace(/\.+$/, "");

const withoutWildcardPrefix = (value: string): string =>
  normalizeDomain(value).replace(/^\*\./, "");

const getLabelCount = (value: string): number =>
  withoutWildcardPrefix(value).split(".").filter(Boolean).length;

export const getSanGroupingKey = (domain: string): string => {
  const normalizedDomain = withoutWildcardPrefix(domain);
  const parts = normalizedDomain.split(".").filter(Boolean);

  if (parts.length <= 2) {
    return normalizedDomain;
  }

  return parts.slice(-2).join(".");
};

const isFirstLevelSubdomainOf = (
  candidate: string,
  baseDomain: string,
): boolean => {
  const normalizedCandidate = withoutWildcardPrefix(candidate);
  const normalizedBase = withoutWildcardPrefix(baseDomain);
  if (!normalizedCandidate.endsWith(`.${normalizedBase}`)) {
    return false;
  }

  return (
    getLabelCount(normalizedCandidate) === getLabelCount(normalizedBase) + 1
  );
};

const isWildcardForBaseDomain = (
  candidate: string,
  baseDomain: string,
): boolean =>
  normalizeDomain(candidate).startsWith("*.") &&
  withoutWildcardPrefix(candidate) === withoutWildcardPrefix(baseDomain);

export const isSanRedundantWithBase = (
  sanDomain: string,
  baseDomain: string,
  wildcardEnabled: boolean,
): string | null => {
  const normalizedSan = normalizeDomain(sanDomain);
  const normalizedBase = withoutWildcardPrefix(baseDomain);

  if (!normalizedBase) {
    return null;
  }

  if (wildcardEnabled && isWildcardForBaseDomain(sanDomain, baseDomain)) {
    return "already covered by primary wildcard";
  }

  // When wildcard is enabled, the primary wildcard (*.example.com) does not
  // cover the apex domain (example.com). Allow the apex domain as a SAN.
  if (!wildcardEnabled && normalizedSan === normalizedBase) {
    return "already covered by the primary domain";
  }

  if (!wildcardEnabled) {
    return null;
  }

  if (
    !normalizeDomain(sanDomain).startsWith("*.") &&
    isFirstLevelSubdomainOf(sanDomain, baseDomain)
  ) {
    return "already covered by primary wildcard";
  }

  return null;
};

export const normalizeSanDomains = (
  rawDomains: string[],
  baseDomain: string,
  wildcardEnabled: boolean,
): SanNormalizationResult => {
  const accepted: string[] = [];
  const conflicts: SanConflict[] = [];
  const seen = new Set<string>();

  for (const rawDomain of rawDomains) {
    const domain = normalizeDomain(rawDomain);
    if (!domain || seen.has(domain)) {
      continue;
    }
    seen.add(domain);

    const redundantReason = isSanRedundantWithBase(
      domain,
      baseDomain,
      wildcardEnabled,
    );
    if (redundantReason) {
      conflicts.push({
        domain,
        reason: redundantReason,
      });
      continue;
    }

    accepted.push(domain);
  }

  return { accepted, conflicts };
};

export const buildSanCredentialGroups = (
  sanDomains: string[],
): SanCredentialGroup[] => {
  const groups = new Map<string, string[]>();

  for (const sanDomain of sanDomains) {
    const domain = normalizeDomain(sanDomain);
    if (!domain) {
      continue;
    }

    const key = getSanGroupingKey(domain);
    const current = groups.get(key) ?? [];
    current.push(domain);
    groups.set(key, current);
  }

  return Array.from(groups.entries())
    .map(([key, domains]) => ({
      key,
      domains: Array.from(new Set(domains)).sort((left, right) =>
        left.localeCompare(right),
      ),
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
};
