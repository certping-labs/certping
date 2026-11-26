/**
 * @jest-environment jsdom
 */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getConditionalRefetchInterval } from "@/hooks/query-polling";

describe("query polling helpers", () => {
  const originalVisibilityState = Object.getOwnPropertyDescriptor(
    document,
    "visibilityState",
  );

  afterEach(() => {
    if (originalVisibilityState) {
      Object.defineProperty(
        document,
        "visibilityState",
        originalVisibilityState,
      );
    }
  });

  it("leaves background pausing to TanStack Query", () => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });

    const interval = getConditionalRefetchInterval(
      { state: { data: ["pending"] } },
      5000,
      (items) => Boolean(items?.length),
    );

    expect(interval).toBe(5000);
  });

  it("allows polling while the browser tab is visible", () => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });

    const interval = getConditionalRefetchInterval(
      { state: { data: ["pending"] } },
      5000,
      (items) => Boolean(items?.length),
    );

    expect(interval).toBe(5000);
  });

  it("continues polling from the last successful data after an error", () => {
    const query = {
      state: {
        data: ["pending"],
        dataUpdateCount: 1,
        error: null as unknown,
        errorUpdateCount: 0,
      },
    };
    expect(
      getConditionalRefetchInterval(query, 5000, (items) =>
        Boolean(items?.length),
      ),
    ).toBe(5000);

    query.state.error = new Error("Temporary network failure");
    query.state.errorUpdateCount = 1;
    const interval = getConditionalRefetchInterval(query, 5000, (items) =>
      Boolean(items?.length),
    );

    expect(interval).toBe(10_000);
  });

  it("caps repeated-error backoff and resets after fresh data", () => {
    const query = {
      state: {
        data: ["pending"],
        dataUpdateCount: 1,
        error: null as unknown,
        errorUpdateCount: 0,
      },
    };
    const getInterval = () =>
      getConditionalRefetchInterval(query, 5000, (items) =>
        Boolean(items?.length),
      );

    expect(getInterval()).toBe(5000);
    query.state.error = new Error("First failure");
    query.state.errorUpdateCount = 1;
    expect(getInterval()).toBe(10_000);
    query.state.error = new Error("Second failure");
    query.state.errorUpdateCount = 2;
    expect(getInterval()).toBe(20_000);
    query.state.error = new Error("Third failure");
    query.state.errorUpdateCount = 3;
    expect(getInterval()).toBe(30_000);
    query.state.error = new Error("Fourth failure");
    query.state.errorUpdateCount = 4;
    expect(getInterval()).toBe(30_000);

    query.state.dataUpdateCount = 2;
    query.state.error = null;
    expect(getInterval()).toBe(5000);
  });

  it("resets failure tracking when TanStack Query resets its counters", () => {
    const query = {
      state: {
        data: ["pending"],
        dataUpdateCount: 2,
        error: new Error("Failure") as unknown,
        errorUpdateCount: 2,
      },
    };
    const getInterval = () =>
      getConditionalRefetchInterval(query, 5000, (items) =>
        Boolean(items?.length),
      );

    expect(getInterval()).toBe(10_000);
    query.state.dataUpdateCount = 0;
    query.state.errorUpdateCount = 0;
    query.state.error = null;

    expect(getInterval()).toBe(5000);
  });

  it("stops polling when the last successful data is terminal", () => {
    const interval = getConditionalRefetchInterval(
      { state: { data: [] } },
      5000,
      (items) => Boolean(items?.length),
    );

    expect(interval).toBe(false);
  });
});
