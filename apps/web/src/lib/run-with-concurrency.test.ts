// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  runWithConcurrency,
  TaskTimeoutError,
} from "@/lib/run-with-concurrency";

/** A promise the test settles by hand, so ordering is explicit, not timed. */
function deferred() {
  let resolve!: () => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

describe("runWithConcurrency", () => {
  it("never has more than the limit in flight and starts the next as one settles", async () => {
    const gates = new Map<number, ReturnType<typeof deferred>>();
    let inFlight = 0;
    let maxInFlight = 0;
    const items = Array.from({ length: 12 }, (_, index) => index);

    const run = runWithConcurrency(
      items,
      async (item) => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        const gate = deferred();
        gates.set(item, gate);
        await gate.promise.finally(() => {
          inFlight -= 1;
        });
      },
      { concurrency: 5, timeoutMs: 1_000 },
    );

    await flush();
    expect([...gates.keys()]).toEqual([0, 1, 2, 3, 4]);

    gates.get(2)?.resolve();
    await flush();
    expect(gates.has(5)).toBe(true);
    expect(gates.has(6)).toBe(false);

    for (let item = 0; item < items.length; item += 1) {
      gates.get(item)?.resolve();
      await flush();
    }

    const result = await run;
    expect(maxInFlight).toBe(5);
    expect(result.succeeded).toHaveLength(12);
    expect(result.failed).toEqual([]);
  });

  it("continues past failures and reports each settle", async () => {
    const onSettled = jest.fn();
    const failure = new Error("boom");

    const result = await runWithConcurrency(
      ["a", "b", "c"],
      async (item) => {
        if (item === "b") throw failure;
      },
      { concurrency: 2, timeoutMs: 1_000, onSettled },
    );

    expect(result.succeeded.sort()).toEqual(["a", "c"]);
    expect(result.failed).toEqual([{ item: "b", error: failure }]);
    expect(onSettled.mock.calls.map(([count]) => count)).toEqual([1, 2, 3]);
  });

  it("fails a task that outlives its timeout", async () => {
    jest.useFakeTimers();
    try {
      const run = runWithConcurrency(
        ["slow"],
        () => new Promise<void>(() => undefined),
        { concurrency: 1, timeoutMs: 30_000 },
      );
      await jest.advanceTimersByTimeAsync(30_000);
      const result = await run;
      expect(result.failed[0]?.error).toBeInstanceOf(TaskTimeoutError);
    } finally {
      jest.useRealTimers();
    }
  });

  it("starts nothing new after an abort but lets in-flight tasks finish", async () => {
    const controller = new AbortController();
    const gates = new Map<string, ReturnType<typeof deferred>>();

    const run = runWithConcurrency(
      ["a", "b", "c", "d"],
      async (item) => {
        const gate = deferred();
        gates.set(item, gate);
        await gate.promise;
      },
      { concurrency: 2, timeoutMs: 1_000, signal: controller.signal },
    );

    await flush();
    controller.abort();
    gates.get("a")?.resolve();
    gates.get("b")?.resolve();

    const result = await run;
    expect(result.succeeded.sort()).toEqual(["a", "b"]);
    expect(result.skipped.sort()).toEqual(["c", "d"]);
    expect(gates.has("c")).toBe(false);
  });

  it("returns an empty result for no items", async () => {
    const task = jest.fn();
    await expect(
      runWithConcurrency([], task, { concurrency: 5, timeoutMs: 1_000 }),
    ).resolves.toEqual({ succeeded: [], failed: [], skipped: [] });
    expect(task).not.toHaveBeenCalled();
  });
});
