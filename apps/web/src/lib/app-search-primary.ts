// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  type AppSearchContext,
  type AppSearchItem,
  createAppSearchItem,
} from "@/lib/app-search-types";

export function getPrimarySearchItems({
  hasOrganization,
}: AppSearchContext): AppSearchItem[] {
  if (!hasOrganization) return [];
  return [
    createAppSearchItem(
      "Overview",
      "Your certificates, deployments and alerts at a glance.",
      "/dashboard",
      "Primary",
      ["home", "dashboard", "summary"],
    ),
  ];
}
