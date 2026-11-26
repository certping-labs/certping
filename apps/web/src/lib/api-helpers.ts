// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

const DEFAULT_SESSION_TTL_SECONDS = 3600;

/** A correlation ID no other browser can mint: `corr-` and a random UUID. */
export function generateCorrelationId(): string {
  return `corr-${randomUuid()}`;
}

function randomUuid(): string {
  try {
    return crypto.randomUUID();
  } catch {
    // An insecure context or an old browser has no randomUUID.
    return uuidFromBytes(randomBytes(16));
  }
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  try {
    crypto.getRandomValues(bytes);
  } catch {
    for (let i = 0; i < length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return bytes;
}

function uuidFromBytes(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4),
    hex.slice(4, 6),
    hex.slice(6, 8),
    hex.slice(8, 10),
    hex.slice(10, 16),
  ]
    .map((part) => part.join(""))
    .join("-");
}

export function normalizeExpiresInMs(expiresIn?: number): number {
  if (!Number.isFinite(expiresIn) || (expiresIn ?? 0) <= 0) {
    return DEFAULT_SESSION_TTL_SECONDS * 1000;
  }

  const ttl = Number(expiresIn);
  return ttl > 100_000 ? ttl : ttl * 1000;
}

const NUMERIC_ID_PATTERN = /^\d+$/;

export function normalizeOrganizationIds(payload: unknown): unknown {
  if (Array.isArray(payload)) {
    return payload.map(normalizeOrganizationIds);
  }

  if (
    payload === null ||
    typeof payload !== "object" ||
    Object.getPrototypeOf(payload) !== Object.prototype
  ) {
    return payload;
  }

  return Object.fromEntries(
    Object.entries(payload).map(([key, value]) => [
      key,
      key === "organizationId" &&
      typeof value === "string" &&
      NUMERIC_ID_PATTERN.test(value.trim())
        ? Number(value)
        : normalizeOrganizationIds(value),
    ]),
  );
}
