// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { SsoUser } from "@/types/auth";

export type AppSearchGroup =
  | "Primary"
  | "Certificate Lifecycle"
  | "Machine Identity"
  | "Integrations"
  | "Operations"
  | "Administration";

export interface AppSearchItem {
  readonly title: string;
  readonly description: string;
  readonly href: string;
  readonly group: AppSearchGroup;
  readonly keywords: readonly string[];
}

export interface AppSearchOptions {
  readonly isFeatureEnabled: (featureKey: string) => boolean;
  /** Whether a result's route would render (`useIsRouteAvailable`). */
  readonly isRouteAvailable: (href: string) => boolean;
  readonly isFeatureFlagsReady?: boolean;
  readonly isSuperAdmin?: boolean;
  readonly user: SsoUser | null | undefined;
}

export interface AppSearchContext extends AppSearchOptions {
  readonly hasOrganization: boolean;
  readonly isFeatureFlagsReady: boolean;
}

export const createAppSearchItem = (
  title: string,
  description: string,
  href: string,
  group: AppSearchGroup,
  keywords: readonly string[],
): AppSearchItem => ({ title, description, href, group, keywords });
