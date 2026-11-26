// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { create } from "zustand";
import {
  type FeatureFlagStatus,
  resolveFeatureAvailability,
} from "@/lib/feature-availability";
import type { EffectiveFlagMap } from "@/lib/feature-flags";

/**
 * How long a feature stays off after an endpoint answered `423` for it. A
 * flag read can lag the endpoint's own check (cache, replica, a toggle racing
 * the request); without this window a stale "on" would remount the page, its
 * request would 423 again, and the two would loop.
 */
export const FEATURE_LOCK_COOLDOWN_MS = 60_000;

interface FeatureFlagState {
  effectiveMap: EffectiveFlagMap;
  status: FeatureFlagStatus;
  /**
   * True once a successful fetch has populated the store this session. A
   * failed refetch after that keeps the last-known values instead of turning
   * every gate into an error.
   */
  hasLoaded: boolean;
  /** When each feature last answered `423`, in epoch ms. */
  lockedAt: Readonly<Record<string, number>>;
  /**
   * Stores a fetched flag set. A key that answered `423` within the cooldown
   * stays off whatever the fetch says.
   */
  setEffectiveMap: (effectiveMap: EffectiveFlagMap, now?: number) => void;
  /** Records a failed fetch; only a session with nothing loaded turns `error`. */
  markLoadFailed: () => void;
  /** The session has no organization, so org flags do not apply. */
  markNotApplicable: () => void;
  /**
   * Applies a `423` for `featureKey` at once and starts (or extends) its
   * cooldown. Returns true only when this closed a feature that was open, so
   * the caller refetches once per close rather than once per `423`.
   */
  markFeatureLocked: (featureKey: string, now?: number) => boolean;
  /**
   * Ends a feature's cooldown, for when this session turned the feature on
   * itself: the next fetch may open it straight away.
   */
  clearFeatureLock: (featureKey: string) => void;
  /** Ends every cooldown, for a bulk turn-on. */
  clearAllFeatureLocks: () => void;
  /**
   * True only when the feature is confirmed on - see
   * {@link resolveFeatureAvailability}. Unknown, failed, and missing keys are
   * all false, so a caller outside React (an API guard, a query's `enabled`)
   * can never fail open.
   */
  isEnabled: (featureKey: string) => boolean;
  /** Back to the signed-out state, cooldowns included (logout, org change). */
  reset: () => void;
}

const initialState = {
  effectiveMap: {} as EffectiveFlagMap,
  status: "pending" as FeatureFlagStatus,
  hasLoaded: false,
  lockedAt: {} as Readonly<Record<string, number>>,
};

function activeLocks(
  lockedAt: Readonly<Record<string, number>>,
  now: number,
): Record<string, number> {
  const active: Record<string, number> = {};
  for (const [featureKey, lockedTime] of Object.entries(lockedAt)) {
    if (now - lockedTime < FEATURE_LOCK_COOLDOWN_MS) {
      active[featureKey] = lockedTime;
    }
  }
  return active;
}

function withoutKey(
  record: Readonly<Record<string, number>>,
  featureKey: string,
): Record<string, number> {
  const rest = { ...record };
  delete rest[featureKey];
  return rest;
}

/**
 * Last-known effective flag values, readable from anywhere without
 * prop-drilling. React Query owns fetching and freshness
 * (`useFeatureFlagsSync`); this store only mirrors the latest answer, its
 * load status, and the `423` cooldowns that override it.
 */
export const useFeatureFlagStore = create<FeatureFlagState>()((set, get) => ({
  ...initialState,

  setEffectiveMap: (effectiveMap, now = Date.now()) =>
    set((state) => {
      const lockedAt = activeLocks(state.lockedAt, now);
      const merged: Record<string, boolean> = { ...effectiveMap };
      for (const featureKey of Object.keys(lockedAt))
        merged[featureKey] = false;
      return {
        effectiveMap: merged,
        lockedAt,
        status: "ready",
        hasLoaded: true,
      };
    }),

  markLoadFailed: () =>
    set((state) => (state.hasLoaded ? state : { status: "error" })),

  markNotApplicable: () => set({ ...initialState, status: "not-applicable" }),

  markFeatureLocked: (featureKey, now = Date.now()) => {
    const state = get();
    const isClosing =
      state.status === "ready" && state.effectiveMap[featureKey] !== false;
    set({
      lockedAt: { ...state.lockedAt, [featureKey]: now },
      ...(isClosing && {
        effectiveMap: { ...state.effectiveMap, [featureKey]: false },
      }),
    });
    return isClosing;
  },

  clearFeatureLock: (featureKey) =>
    set((state) =>
      featureKey in state.lockedAt
        ? { lockedAt: withoutKey(state.lockedAt, featureKey) }
        : state,
    ),

  clearAllFeatureLocks: () => set({ lockedAt: {} }),

  isEnabled: (featureKey: string) => {
    const { status, effectiveMap } = get();
    return (
      resolveFeatureAvailability(status, effectiveMap, featureKey) === "on"
    );
  },

  reset: () => set(initialState),
}));
