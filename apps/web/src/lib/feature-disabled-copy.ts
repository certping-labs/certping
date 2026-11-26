// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Copy for the "this feature is off" surface (`FeatureDisabledPage`). Kept in
 * a plain module, free of React, so the Playwright suite asserts the exact
 * wording the app renders instead of a copy of it that can drift.
 */
export const FEATURE_DISABLED_BODY =
  "This feature isn't available. To request access, ask your CertPing administrator.";

/** Heading of the not-available surface, e.g. "Certificate discovery isn't available". */
export function featureDisabledTitle(featureLabel: string): string {
  return `${featureLabel} isn't available`;
}
