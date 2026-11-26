// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export interface NavMatchEntry {
  url?: string;
  exact?: boolean;
  matchPrefix?: string;
  subMenu?: readonly NavMatchEntry[];
}

const pathOf = (url: string) => url.split("?")[0] ?? url;

const matchLength = (pathname: string, base: string, exact = false) => {
  if (pathname === base) return base.length;
  if (!exact && pathname.startsWith(`${base}/`)) return base.length;
  return -1;
};

export function resolveActiveNavUrl(
  pathname: string,
  entries: readonly NavMatchEntry[],
): string | null {
  let best: string | null = null;
  let bestLength = -1;
  const visit = (entry: NavMatchEntry) => {
    entry.subMenu?.forEach(visit);
    if (!entry.url) return;
    const length = Math.max(
      matchLength(pathname, pathOf(entry.url), entry.exact),
      entry.matchPrefix ? matchLength(pathname, entry.matchPrefix) : -1,
    );
    if (length > bestLength) {
      best = entry.url;
      bestLength = length;
    }
  };
  entries.forEach(visit);
  return best;
}
