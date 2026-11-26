// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  FEATURE_LOCK_COOLDOWN_MS,
  useFeatureFlagStore,
} from "@/stores/feature-flag-store";

const store = () => useFeatureFlagStore.getState();

describe("useFeatureFlagStore", () => {
  beforeEach(() => {
    store().reset();
  });

  describe("isEnabled", () => {
    it("is false while the first answer is pending (never fails open)", () => {
      expect(store().status).toBe("pending");
      expect(store().isEnabled("ANY_KEY")).toBe(false);
    });

    it("is true for a key the map turns on", () => {
      store().setEffectiveMap({ FEATURE_A: true });
      expect(store().isEnabled("FEATURE_A")).toBe(true);
    });

    it("is false for a key the map turns off", () => {
      store().setEffectiveMap({ FEATURE_B: false });
      expect(store().isEnabled("FEATURE_B")).toBe(false);
    });

    it("treats a key missing from a loaded map as off", () => {
      store().setEffectiveMap({});
      expect(store().isEnabled("UNKNOWN_KEY")).toBe(false);
    });

    it("is true for every key when org flags do not apply", () => {
      store().markNotApplicable();
      expect(store().status).toBe("not-applicable");
      expect(store().isEnabled("ANY_KEY")).toBe(true);
    });
  });

  describe("markLoadFailed", () => {
    it("turns a session with nothing loaded into an error, not open", () => {
      store().markLoadFailed();
      expect(store().status).toBe("error");
      expect(store().isEnabled("ANY_KEY")).toBe(false);
    });

    it("keeps last-known values when a later refetch fails", () => {
      store().setEffectiveMap({ FEATURE_A: true });
      store().markLoadFailed();
      expect(store().status).toBe("ready");
      expect(store().isEnabled("FEATURE_A")).toBe(true);
    });

    it("recovers to ready on the next successful load", () => {
      store().markLoadFailed();
      store().setEffectiveMap({ FEATURE_A: true });
      expect(store().status).toBe("ready");
      expect(store().isEnabled("FEATURE_A")).toBe(true);
    });
  });

  describe("markFeatureLocked (423 cooldown)", () => {
    const T0 = 1_000_000;

    it("closes one loaded key, keeps the others, and asks for one refetch", () => {
      store().setEffectiveMap({ FEATURE_A: true, FEATURE_B: true }, T0);
      expect(store().markFeatureLocked("FEATURE_A", T0)).toBe(true);
      expect(store().isEnabled("FEATURE_A")).toBe(false);
      expect(store().isEnabled("FEATURE_B")).toBe(true);
    });

    it("does not ask for another refetch while the key is already closed", () => {
      store().setEffectiveMap({ FEATURE_A: true }, T0);
      store().markFeatureLocked("FEATURE_A", T0);
      const before = store().effectiveMap;
      expect(store().markFeatureLocked("FEATURE_A", T0 + 1_000)).toBe(false);
      expect(store().effectiveMap).toBe(before);
    });

    it("keeps a stale 'on' from reopening the key inside the window", () => {
      store().setEffectiveMap({ FEATURE_A: true }, T0);
      store().markFeatureLocked("FEATURE_A", T0);
      store().setEffectiveMap({ FEATURE_A: true }, T0 + 30_000);
      expect(store().isEnabled("FEATURE_A")).toBe(false);
    });

    it("lets a repeated 423 extend the window", () => {
      store().setEffectiveMap({ FEATURE_A: true }, T0);
      store().markFeatureLocked("FEATURE_A", T0);
      store().markFeatureLocked("FEATURE_A", T0 + 50_000);
      store().setEffectiveMap(
        { FEATURE_A: true },
        T0 + FEATURE_LOCK_COOLDOWN_MS + 1,
      );
      expect(store().isEnabled("FEATURE_A")).toBe(false);
    });

    it("reopens on the first 'on' fetch after the window", () => {
      store().setEffectiveMap({ FEATURE_A: true }, T0);
      store().markFeatureLocked("FEATURE_A", T0);
      store().setEffectiveMap(
        { FEATURE_A: true },
        T0 + FEATURE_LOCK_COOLDOWN_MS,
      );
      expect(store().isEnabled("FEATURE_A")).toBe(true);
      expect(store().lockedAt).toEqual({});
    });

    it("applies a 423 that arrives before the first load once it lands", () => {
      expect(store().markFeatureLocked("FEATURE_A", T0)).toBe(false);
      expect(store().status).toBe("pending");
      store().setEffectiveMap({ FEATURE_A: true }, T0 + 1_000);
      expect(store().isEnabled("FEATURE_A")).toBe(false);
    });

    it("ends one key's window when this session turns it on", () => {
      store().setEffectiveMap({ FEATURE_A: true, FEATURE_B: true }, T0);
      store().markFeatureLocked("FEATURE_A", T0);
      store().markFeatureLocked("FEATURE_B", T0);
      store().clearFeatureLock("FEATURE_A");
      store().setEffectiveMap({ FEATURE_A: true, FEATURE_B: true }, T0 + 1);
      expect(store().isEnabled("FEATURE_A")).toBe(true);
      expect(store().isEnabled("FEATURE_B")).toBe(false);
    });

    it("leaves state untouched when clearing a key with no window", () => {
      store().setEffectiveMap({ FEATURE_A: true }, T0);
      const before = store().lockedAt;
      store().clearFeatureLock("FEATURE_A");
      expect(store().lockedAt).toBe(before);
    });

    it("ends every window on a bulk turn-on", () => {
      store().setEffectiveMap({ FEATURE_A: true }, T0);
      store().markFeatureLocked("FEATURE_A", T0);
      store().clearAllFeatureLocks();
      store().setEffectiveMap({ FEATURE_A: true }, T0 + 1);
      expect(store().isEnabled("FEATURE_A")).toBe(true);
    });
  });

  describe("reset", () => {
    it("returns to pending with nothing loaded and no cooldowns", () => {
      store().setEffectiveMap({ DISCOVERY: true });
      store().markFeatureLocked("DISCOVERY");
      store().reset();
      expect(store()).toMatchObject({
        effectiveMap: {},
        status: "pending",
        hasLoaded: false,
        lockedAt: {},
      });
    });
  });
});
