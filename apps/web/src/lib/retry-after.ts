// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, AxiosHeaders } from "axios";

/** Seconds a 429 asks the caller to wait, from its Retry-After header; null when absent. */
export const getRetryAfterSeconds = (error: unknown): number | null => {
  if (!(error instanceof AxiosError) || error.response?.status !== 429) {
    return null;
  }
  const { headers } = error.response;
  const seconds = Number(
    headers instanceof AxiosHeaders
      ? headers.get("retry-after")
      : headers?.["retry-after"],
  );
  return Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds) : null;
};

// Past this, a clock time reads faster than a count of seconds.
const SECONDS_SHOWN_UNDER = 90;

const clockTime = new Intl.DateTimeFormat("en-US", {
  hour: "numeric",
  minute: "2-digit",
});

/** "Try again in 40 seconds." or "Try again after 3:42 PM." */
export const formatRetryWait = (until: number, now: number): string => {
  const seconds = Math.max(1, Math.ceil((until - now) / 1000));
  return seconds < SECONDS_SHOWN_UNDER
    ? `Try again in ${seconds} ${seconds === 1 ? "second" : "seconds"}.`
    : `Try again after ${clockTime.format(new Date(until))}.`;
};
