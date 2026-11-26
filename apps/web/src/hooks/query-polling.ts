// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

type QueryStateWithData<TData> = {
  state: {
    data: TData | undefined;
    dataUpdateCount?: number;
    error?: unknown;
    errorUpdateCount?: number;
  };
};

interface PollingFailureTracker {
  readonly dataUpdateCount: number;
  readonly errorUpdateCount: number;
  readonly consecutiveFailures: number;
}

const MAX_POLLING_BACKOFF_MS = 30_000;
// TanStack resets fetchFailureCount at the start of every refetch, so retain
// consecutive completed failures per Query without keeping discarded queries alive.
const pollingFailureTrackers = new WeakMap<object, PollingFailureTracker>();

const calculateConsecutiveFailures = (
  previousTracker: PollingFailureTracker,
  dataUpdateCount: number,
  errorUpdateCount: number,
  hasCurrentError: boolean,
): number => {
  const wasQueryReset =
    dataUpdateCount < previousTracker.dataUpdateCount ||
    errorUpdateCount < previousTracker.errorUpdateCount;
  if (wasQueryReset) {
    return hasCurrentError ? 1 : 0;
  }
  if (dataUpdateCount > previousTracker.dataUpdateCount) {
    return 0;
  }
  return (
    previousTracker.consecutiveFailures +
    Math.max(0, errorUpdateCount - previousTracker.errorUpdateCount)
  );
};

const getConsecutivePollingFailures = <TData>(
  query: QueryStateWithData<TData>,
): number => {
  const dataUpdateCount = query.state.dataUpdateCount ?? 0;
  const errorUpdateCount = query.state.errorUpdateCount ?? 0;
  const previousTracker = pollingFailureTrackers.get(query);
  if (!previousTracker) {
    const consecutiveFailures = query.state.error ? 1 : 0;
    pollingFailureTrackers.set(query, {
      dataUpdateCount,
      errorUpdateCount,
      consecutiveFailures,
    });
    return consecutiveFailures;
  }

  const consecutiveFailures = calculateConsecutiveFailures(
    previousTracker,
    dataUpdateCount,
    errorUpdateCount,
    Boolean(query.state.error),
  );

  pollingFailureTrackers.set(query, {
    dataUpdateCount,
    errorUpdateCount,
    consecutiveFailures,
  });
  return consecutiveFailures;
};

export function getConditionalRefetchInterval<TData>(
  query: QueryStateWithData<TData>,
  intervalMs: number,
  shouldPoll: (data: TData | undefined) => boolean,
): number | false {
  const failureCount = getConsecutivePollingFailures(query);
  if (!shouldPoll(query.state.data)) {
    return false;
  }

  const backoffMs = intervalMs * 2 ** Math.min(failureCount, 10);
  return Math.min(backoffMs, Math.max(intervalMs, MAX_POLLING_BACKOFF_MS));
}
