// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  adaptiveRefetchInterval,
  ambientRefetchInterval,
  isRunWorthPolling,
  liveRefetchInterval,
  POLLED_QUERY_OPTIONS,
} from "@/lib/machine-identity/polling";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";

const { activeMs, liveMs, ambientMs, maxActiveMs } =
  MACHINE_IDENTITY_CONFIG.polling;

function query<T>(data: T | undefined, error?: unknown) {
  return {
    state: {
      data,
      dataUpdateCount: error ? 0 : 1,
      errorUpdateCount: error ? 1 : 0,
      error,
    },
  };
}

describe("polled query options", () => {
  it("never polls a hidden tab", () => {
    // The whole cost model depends on this: an operator with eight tabs open
    // should be paying for the one they are looking at.
    expect(POLLED_QUERY_OPTIONS.refetchIntervalInBackground).toBe(false);
  });

  it("reconciles on focus so returning to a tab is instant", () => {
    expect(POLLED_QUERY_OPTIONS.refetchOnWindowFocus).toBe(true);
  });
});

describe("adaptiveRefetchInterval", () => {
  it("polls fast only while something is in flight", () => {
    expect(adaptiveRefetchInterval(query("busy"), () => true)).toBe(activeMs);
    expect(adaptiveRefetchInterval(query("idle"), () => false)).toBe(liveMs);
  });

  it("uses the caller's resting cadence when one is given", () => {
    expect(adaptiveRefetchInterval(query("idle"), () => false, ambientMs)).toBe(
      ambientMs,
    );
  });

  it("backs off instead of hammering a failing backend", () => {
    // Every open tab retrying on the same tight interval is how a struggling
    // API stays down.
    const failing = adaptiveRefetchInterval(
      query(undefined, new Error("500")),
      () => true,
    );
    expect(failing).toBeGreaterThan(activeMs);
  });
});

describe("resting cadences", () => {
  it("separates data the user is watching from supporting aggregates", () => {
    expect(liveRefetchInterval(query("x"))).toBe(liveMs);
    expect(ambientRefetchInterval(query("x"))).toBe(ambientMs);
    expect(ambientMs).toBeGreaterThan(liveMs);
    expect(liveMs).toBeGreaterThan(activeMs);
  });
});

describe("isRunWorthPolling", () => {
  it("follows a run that just started", () => {
    expect(isRunWorthPolling(new Date().toISOString())).toBe(true);
  });

  it("gives up on a run that never reached a terminal state", () => {
    // A sync whose agent died stays PENDING forever; without this bound every
    // tab left open on that source polls every few seconds indefinitely.
    const stuck = new Date(Date.now() - maxActiveMs - 1_000).toISOString();
    expect(isRunWorthPolling(stuck)).toBe(false);
  });

  it("treats an absent or unparseable timestamp as not worth polling", () => {
    expect(isRunWorthPolling(null)).toBe(false);
    expect(isRunWorthPolling(undefined)).toBe(false);
    expect(isRunWorthPolling("not a date")).toBe(false);
  });
});
