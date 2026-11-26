// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useCallback, useEffect, useRef } from "react";
import { useIsFetching, useQuery, useQueryClient } from "@tanstack/react-query";
import { getEffectiveFeatureFlags } from "@/lib/backend/feature-flags";
import {
  type FeatureAvailability,
  resolveFeatureAvailability,
} from "@/lib/feature-availability";
import { hasOrganizationContext } from "@/lib/authz";
import { isRouteFeatureOn } from "@/lib/feature-routes";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { useAuth } from "@/hooks/use-auth";

/**
 * How long a fetched flag set is treated as fresh. Short, because the cost of
 * acting on a stale flag (showing a feature the API will reject) is higher
 * than one small request.
 */
const FEATURE_FLAGS_STALE_MS = 30_000;

/**
 * Background cadence while the tab is focused. A flag toggled by an
 * administrator in another session surfaces here within a minute. The poll
 * also keeps running after a failed first fetch, so an `error` state heals on
 * its own.
 */
const FEATURE_FLAGS_POLL_MS = 60_000;

/** Prefix shared by every flag query. Mutations invalidate this. */
export const FEATURE_FLAGS_QUERY_PREFIX = ["feature-flags"] as const;

/** Query key for the organization's effective flag map. */
export const featureFlagsQueryKey = (organizationId?: string | null) =>
  [...FEATURE_FLAGS_QUERY_PREFIX, "effective", organizationId ?? null] as const;

/**
 * The app's single flag fetcher. Mount it once, high in the authenticated
 * tree (`AuthProvider`); every other hook here only reads the store, so a
 * component asking "is X on?" never adds a query observer.
 *
 * Reads `GET /feature-flags/effective`, which any member of an organization
 * may call, and writes the answer and its load status into
 * {@link useFeatureFlagStore}: success → `ready`; a failed first fetch →
 * `error` (a failed refetch keeps the last-known values); a session without
 * an organization → `not-applicable`. Switching organization starts over.
 */
export function useFeatureFlagsSync(): void {
  const { isAuthenticated, user } = useAuth();
  const organizationId = user?.organizationId;
  const hasOrgContext = Boolean(organizationId);
  const setEffectiveMap = useFeatureFlagStore((s) => s.setEffectiveMap);
  const markLoadFailed = useFeatureFlagStore((s) => s.markLoadFailed);
  const markNotApplicable = useFeatureFlagStore((s) => s.markNotApplicable);
  const previousOrganizationId = useRef(organizationId);

  const query = useQuery({
    queryKey: featureFlagsQueryKey(organizationId),
    queryFn: getEffectiveFeatureFlags,
    // Never gated on a store-side TTL: that switched the query off after its
    // first success and silently killed the poll below.
    enabled: isAuthenticated && hasOrgContext,
    staleTime: FEATURE_FLAGS_STALE_MS,
    refetchInterval: FEATURE_FLAGS_POLL_MS,
    // A hidden tab cannot be acting on a stale flag.
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
    retry: false,
  });

  // Another organization's flags must never gate this one, so a real switch
  // (not the first mount) clears the answer and every 423 cooldown.
  useEffect(() => {
    if (previousOrganizationId.current === organizationId) return;
    previousOrganizationId.current = organizationId;
    useFeatureFlagStore.getState().reset();
  }, [organizationId]);

  // Keyed on the update time, not the data: an identical refetch keeps the
  // same object, and it still has to re-apply once a 423 cooldown has ended.
  useEffect(() => {
    if (query.data) setEffectiveMap(query.data);
  }, [query.data, query.dataUpdatedAt, setEffectiveMap]);

  useEffect(() => {
    if (query.isError) markLoadFailed();
  }, [query.isError, query.errorUpdateCount, markLoadFailed]);

  useEffect(() => {
    if (isAuthenticated && !hasOrgContext) markNotApplicable();
  }, [isAuthenticated, hasOrgContext, markNotApplicable]);
}

/**
 * Read-only view of the flag store for components that test several keys.
 * `isEnabled` changes identity whenever the answer can change, so it is safe
 * as a memo dependency. It is true only for a confirmed-on key.
 */
export function useFeatureFlags() {
  const effectiveMap = useFeatureFlagStore((s) => s.effectiveMap);
  const status = useFeatureFlagStore((s) => s.status);

  const availabilityOf = useCallback(
    (featureKey: string) =>
      resolveFeatureAvailability(status, effectiveMap, featureKey),
    [effectiveMap, status],
  );
  const isEnabled = useCallback(
    (featureKey: string) => availabilityOf(featureKey) === "on",
    [availabilityOf],
  );

  return {
    status,
    /** Four-state answer per key, for copy that differs between on and off. */
    availabilityOf,
    /** False only while the first answer is pending. */
    isReady: status !== "pending",
    isEnabled,
  };
}

/**
 * Four-state answer for one key. Subscribes to a single string, so the
 * caller re-renders only when this feature's answer changes.
 */
export function useFeatureAvailability(
  featureKey: string,
): FeatureAvailability {
  return useFeatureFlagStore((s) =>
    resolveFeatureAvailability(s.status, s.effectiveMap, featureKey),
  );
}

/**
 * True only once the feature is confirmed on. Use it to show an option and as
 * a query's `enabled`, so a gated endpoint is never called while its flag is
 * unknown or off (no 423 noise).
 */
export function useIsFeatureEnabled(featureKey: string): boolean {
  return useFeatureAvailability(featureKey) === "on";
}

/**
 * `(href) => boolean`: whether a link to `href` would render, by the same
 * rule `FeatureRouteGate` enforces (flags, super-admin exemptions, routes
 * that need an organization). Navigation and search filter through it.
 */
export function useIsRouteAvailable(): (href: string) => boolean {
  const effectiveMap = useFeatureFlagStore((s) => s.effectiveMap);
  const status = useFeatureFlagStore((s) => s.status);
  const isSuperAdmin = useAuthStore((s) => Boolean(s.isSuperAdmin));
  return useCallback(
    (href: string) =>
      isRouteFeatureOn(href, { status, effectiveMap, isSuperAdmin }),
    [effectiveMap, isSuperAdmin, status],
  );
}

/**
 * For an organization-scoped query's `enabled`: the feature is confirmed on
 * and the session has an organization. Without one the flag answers "on"
 * (org flags do not apply), but these endpoints refuse the request.
 */
export function useIsOrgFeatureEnabled(featureKey: string): boolean {
  const isFeatureOn = useIsFeatureEnabled(featureKey);
  const hasOrganization = useAuthStore((s) => hasOrganizationContext(s.user));
  return isFeatureOn && hasOrganization;
}

/** Refetches the flag set from an error state. */
export function useRetryFeatureFlags() {
  const queryClient = useQueryClient();
  const isRetrying =
    useIsFetching({ queryKey: FEATURE_FLAGS_QUERY_PREFIX }) > 0;
  const retry = useCallback(() => {
    void queryClient.refetchQueries({ queryKey: FEATURE_FLAGS_QUERY_PREFIX });
  }, [queryClient]);
  return { retry, isRetrying };
}
