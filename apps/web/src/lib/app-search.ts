// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getAdministrationSearchItems } from "@/lib/app-search-administration";
import { getCertificateSearchItems } from "@/lib/app-search-certificates";
import { getMachineIdentitySearchItems } from "@/lib/app-search-machine-identity";
import { getOperationsSearchItems } from "@/lib/app-search-operations";
import { getPrimarySearchItems } from "@/lib/app-search-primary";
import type {
  AppSearchContext,
  AppSearchItem,
  AppSearchOptions,
} from "@/lib/app-search-types";
import { hasOrganizationContext } from "@/lib/authz";

export type { AppSearchGroup, AppSearchItem } from "@/lib/app-search-types";

const searchItemFactories = [
  getPrimarySearchItems,
  getCertificateSearchItems,
  getMachineIdentitySearchItems,
  getOperationsSearchItems,
  getAdministrationSearchItems,
] as const;

export function getAppSearchItems(options: AppSearchOptions): AppSearchItem[] {
  const context: AppSearchContext = {
    ...options,
    hasOrganization: hasOrganizationContext(options.user),
    isFeatureFlagsReady: options.isFeatureFlagsReady ?? true,
  };

  // Every factory checks its own flags; this is the backstop that keeps a
  // result for a gated route out of search when its feature is not on.
  return searchItemFactories
    .flatMap((getSearchItems) => getSearchItems(context))
    .filter((item) => options.isRouteAvailable(item.href));
}
