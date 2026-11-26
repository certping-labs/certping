// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { useFeatureFlagStore } from "@/stores/feature-flag-store";

/**
 * Puts the real flag store in the state a page sees once `FeatureRouteGate`
 * has let it mount: flags loaded, with exactly these keys on. Keys left out
 * are off, as in production.
 */
export function seedFeatureFlags(effectiveMap: Record<string, boolean>): void {
  useFeatureFlagStore.getState().setEffectiveMap(effectiveMap);
}
