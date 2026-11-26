// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  AUDIT_TRAIL_ALL_VISIBILITIES,
  type AuditTrailFilters,
} from "@/types/audit-trail";

export const hasAuditTrailFilters = (filters: AuditTrailFilters): boolean =>
  Object.values(filters).some((value) => Boolean(value?.trim()));

const DEFAULT_PLATFORM_VISIBILITY = "CUSTOMER";

/**
 * The platform view opens on customer events: every API request is an
 * internal row, which would bury them. Internal rows are read on demand.
 */
export const platformVisibility = (visibility: string | undefined): string =>
  visibility?.trim() || DEFAULT_PLATFORM_VISIBILITY;

/** What the platform route is asked for: it reads both when given no visibility. */
export const platformVisibilityParam = (
  visibility: string | undefined,
): string | undefined => {
  const chosen = platformVisibility(visibility);
  return chosen === AUDIT_TRAIL_ALL_VISIBILITIES ? undefined : chosen;
};
