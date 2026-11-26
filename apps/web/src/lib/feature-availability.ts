// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { EffectiveFlagMap } from "@/lib/feature-flags";

/**
 * Where the current session's flag set stands.
 *
 * - `pending`: no answer yet (auth still resolving, or the first fetch is in
 *   flight). Nothing gated may render as on or as off.
 * - `ready`: a fetch has succeeded at least once. A later failed refetch keeps
 *   `ready` with the last-known values, so a blip never unmounts a page.
 * - `error`: the first fetch failed and there are no last-known values.
 * - `not-applicable`: the session has no organization (platform super admin),
 *   so org flags do not apply. Routes that only work inside an organization
 *   (`requiresOrganization` in `FEATURE_ROUTE_RULES`) say so instead of
 *   rendering; the backend still answers 423 where it must.
 */
export type FeatureFlagStatus =
  "pending" | "ready" | "error" | "not-applicable";

/**
 * The answer to "may this feature render?" for one key or a set of keys.
 * Only `on` renders the feature. `pending` renders a skeleton, `off` the
 * not-available page, `error` a retryable failure. None of them fails open.
 */
export type FeatureAvailability = "pending" | "on" | "off" | "error";

/** How a set of flag keys combines: every key on, or at least one on. */
export type FeatureMatch = "all" | "any";

/** A key the map does not carry is off, so a gate stays closed until it loads. */
function isKeyOn(effectiveMap: EffectiveFlagMap, featureKey: string): boolean {
  return effectiveMap[featureKey] === true;
}

export function resolveFeatureAvailability(
  status: FeatureFlagStatus,
  effectiveMap: EffectiveFlagMap,
  featureKey: string,
): FeatureAvailability {
  switch (status) {
    case "not-applicable":
      return "on";
    case "pending":
      return "pending";
    case "error":
      return "error";
    case "ready":
      return isKeyOn(effectiveMap, featureKey) ? "on" : "off";
  }
}

export interface FeatureSetAvailability {
  availability: FeatureAvailability;
  /** The key to name on the not-available page; set only when `off`. */
  blockingKey?: string;
}

/**
 * Resolves several keys at once. With `all`, one key off closes the set; with
 * `any`, one key on opens it. An empty set is ungated and always `on`.
 */
export function resolveFeatureSetAvailability(
  status: FeatureFlagStatus,
  effectiveMap: EffectiveFlagMap,
  featureKeys: readonly string[],
  match: FeatureMatch = "all",
): FeatureSetAvailability {
  if (featureKeys.length === 0 || status === "not-applicable") {
    return { availability: "on" };
  }
  if (status !== "ready") {
    return { availability: status };
  }
  const offKeys = featureKeys.filter((key) => !isKeyOn(effectiveMap, key));
  const isOpen =
    match === "all"
      ? offKeys.length === 0
      : offKeys.length < featureKeys.length;
  return isOpen
    ? { availability: "on" }
    : { availability: "off", blockingKey: offKeys[0] };
}
