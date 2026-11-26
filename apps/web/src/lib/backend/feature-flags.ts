// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import { apiClient, apiRoutes } from "@/lib/api";
import type { EffectiveFlagMap } from "@/lib/feature-flags";

const effectiveFlagsSchema = z.object({
  effectiveMap: z.record(z.string(), z.unknown()).nullish(),
});

/**
 * The resolved on/off state of every flag for the caller's organization:
 * what every gate, the navigation and post-login routing read. Open to any
 * signed-in user with an organization. A super admin without an organization
 * gets an empty map. A value that is not a boolean counts as off.
 */
export async function getEffectiveFeatureFlags(): Promise<EffectiveFlagMap> {
  const res = await apiClient.get<unknown>(
    apiRoutes.query.featureFlags.effective,
  );
  const entries = Object.entries(
    effectiveFlagsSchema.parse(res.data).effectiveMap ?? {},
  );
  return Object.fromEntries(
    entries.map(([featureKey, isOn]) => [featureKey, isOn === true]),
  );
}

/**
 * The post-login flag loader: the effective map for a session with an
 * organization, `null` (org flags do not apply) for one without, so routing
 * decides exactly as `FeatureRouteGate` will.
 */
export function loadSessionFeatureFlags(
  organizationId: string | number | null | undefined,
): () => Promise<EffectiveFlagMap | null> {
  const hasOrganization =
    organizationId != null && String(organizationId).trim() !== "";
  return () =>
    hasOrganization ? getEffectiveFeatureFlags() : Promise.resolve(null);
}
