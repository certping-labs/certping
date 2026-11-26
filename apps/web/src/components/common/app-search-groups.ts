// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { AppSearchGroup, AppSearchItem } from "@/lib/app-search";

// Ordered as the sidebar orders them, so a result's group reads as the place
// the operator would otherwise have navigated to.
const SEARCH_GROUPS: readonly AppSearchGroup[] = [
  "Primary",
  "Certificate Lifecycle",
  "Machine Identity",
  "Integrations",
  "Operations",
  "Administration",
];

export function groupAppSearchItems(items: readonly AppSearchItem[]) {
  const itemsByGroup = new Map<AppSearchGroup, AppSearchItem[]>(
    SEARCH_GROUPS.map((group) => [group, []]),
  );

  items.forEach((item) => itemsByGroup.get(item.group)?.push(item));

  return SEARCH_GROUPS.map((group) => ({
    group,
    items: itemsByGroup.get(group) ?? [],
  })).filter(({ items: groupItems }) => groupItems.length > 0);
}
