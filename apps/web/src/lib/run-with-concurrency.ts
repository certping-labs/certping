// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/** Rejection reason for a task that ran longer than its timeout. */
export class TaskTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Task timed out after ${timeoutMs} ms`);
    this.name = "TaskTimeoutError";
  }
}

export interface ConcurrentRunOptions {
  /** Most tasks in flight at once. */
  concurrency: number;
  /** A task still pending after this long counts as failed. */
  timeoutMs: number;
  /** Once aborted no new task starts; tasks already in flight finish. */
  signal?: AbortSignal;
  /** Called after each task settles with how many have settled so far. */
  onSettled?: (settledCount: number) => void;
}

export interface ConcurrentRunResult<T> {
  succeeded: T[];
  failed: { item: T; error: unknown }[];
  /** Never started because the run was aborted. */
  skipped: T[];
}

function withTimeout<R>(promise: Promise<R>, timeoutMs: number): Promise<R> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new TaskTimeoutError(timeoutMs)),
      timeoutMs,
    );
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Runs `task` over `items` with a fixed number of workers, so at most
 * `concurrency` tasks are ever in flight. A failure or timeout never stops the
 * run; every item ends up succeeded, failed or (after an abort) skipped.
 */
export async function runWithConcurrency<T>(
  items: readonly T[],
  task: (item: T) => Promise<unknown>,
  { concurrency, timeoutMs, signal, onSettled }: ConcurrentRunOptions,
): Promise<ConcurrentRunResult<T>> {
  const result: ConcurrentRunResult<T> = {
    succeeded: [],
    failed: [],
    skipped: [],
  };
  let nextIndex = 0;
  let settledCount = 0;

  const runWorker = async () => {
    while (nextIndex < items.length) {
      const item = items[nextIndex];
      nextIndex += 1;
      if (signal?.aborted) {
        result.skipped.push(item);
        continue;
      }
      try {
        await withTimeout(
          Promise.resolve().then(() => task(item)),
          timeoutMs,
        );
        result.succeeded.push(item);
      } catch (error) {
        result.failed.push({ item, error });
      }
      settledCount += 1;
      onSettled?.(settledCount);
    }
  };

  const workerCount = Math.max(1, Math.min(concurrency, items.length));
  await Promise.all(Array.from({ length: workerCount }, runWorker));
  return result;
}
