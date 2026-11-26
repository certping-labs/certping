// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Shortens an identifier from the middle, keeping its start and end, so
 * "req-http-f740c5eb-6e74-4dd4-a321-b3b48b1d6e69" reads "req-http-f740…6e69":
 * the prefix says what it is, the suffix tells two apart. One of `max`
 * characters or fewer (e.g. "req-405420498018387") is left whole.
 */
export const middleEllipsis = (
  value: string,
  {
    max = 20,
    head = 13,
    tail = 4,
  }: { max?: number; head?: number; tail?: number } = {},
): string =>
  value.length > max
    ? `${value.slice(0, head)}…${value.slice(value.length - tail)}`
    : value;
