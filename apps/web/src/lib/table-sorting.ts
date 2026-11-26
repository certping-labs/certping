// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export function compareDateValues(left: unknown, right: unknown): number {
  const leftTime = toDateTime(left);
  const rightTime = toDateTime(right);

  if (leftTime == null && rightTime == null) {
    return 0;
  }
  if (leftTime == null) {
    return -1;
  }
  if (rightTime == null) {
    return 1;
  }

  return leftTime - rightTime;
}

function toDateTime(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  const parsed = new Date(value);
  const time = parsed.getTime();
  return Number.isNaN(time) ? null : time;
}
