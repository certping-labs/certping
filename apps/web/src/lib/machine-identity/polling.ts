// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Refresh policy for Machine Identity queries.
 *
 * <p>Kept out of the hooks so every surface answers the same two questions the
 * same way: is something in flight right now, and is this worth a request
 * while nothing is?
 */
import { getConditionalRefetchInterval } from "@/hooks/query-polling";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";

const { activeMs, liveMs, ambientMs, maxActiveMs } =
  MACHINE_IDENTITY_CONFIG.polling;

type QueryStateWithData<TData> = Parameters<
  typeof getConditionalRefetchInterval<TData>
>[0];

/**
 * Shared React Query options for anything that refreshes on a timer.
 *
 * <p>`refetchIntervalInBackground: false` is the load-bearing part: a hidden
 * tab cannot be looking at stale data, so it should not be paying the backend
 * for fresh data. `refetchOnWindowFocus` then makes coming back instant
 * without a timer having fired.
 */
export const POLLED_QUERY_OPTIONS = {
  refetchIntervalInBackground: false,
  refetchOnWindowFocus: true,
  retry: false,
} as const;

/**
 * Picks between the in-flight cadence and a slower resting one.
 *
 * <p>Delegates to {@link getConditionalRefetchInterval} so a backend that
 * starts failing gets exponential backoff rather than a tight retry loop from
 * every open tab.
 */
export function adaptiveRefetchInterval<TData>(
  query: QueryStateWithData<TData>,
  isActive: (data: TData | undefined) => boolean,
  restingMs: number = liveMs,
): number | false {
  const interval = isActive(query.state.data) ? activeMs : restingMs;
  return getConditionalRefetchInterval(query, interval, () => true);
}

/** A steady cadence for data the backend changes on its own. */
export function liveRefetchInterval<TData>(
  query: QueryStateWithData<TData>,
): number | false {
  return getConditionalRefetchInterval(query, liveMs, () => true);
}

/** A slow cadence for supporting aggregates and health summaries. */
export function ambientRefetchInterval<TData>(
  query: QueryStateWithData<TData>,
): number | false {
  return getConditionalRefetchInterval(query, ambientMs, () => true);
}

/**
 * True while a run started at `startedAt` is still worth polling for.
 *
 * <p>The bound matters: a sync whose agent died never reaches a terminal
 * status, and without this every tab left open on that source would poll every
 * five seconds forever.
 */
export function isRunWorthPolling(
  startedAt: string | null | undefined,
): boolean {
  if (!startedAt) return false;
  const started = new Date(startedAt).getTime();
  if (Number.isNaN(started)) return false;
  return Date.now() - started <= maxActiveMs;
}
