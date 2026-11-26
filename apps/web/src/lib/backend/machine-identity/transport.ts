// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared request-shaping helpers for the Machine Identity real-backend
 * adapters (pagination, sort, and filter param normalization).
 */
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import type { PageRequestParams } from "@/types/pagination";

export interface ResolvedPageRequest {
  page: number;
  size: number;
  sort?: string;
  direction: "asc" | "desc";
}

/**
 * Clamps a page request into the range the backend will accept.
 *
 * <p>Normalizing here rather than in each hook keeps React Query keys stable:
 * `size: undefined` and `size: 25` must not produce two cache entries.
 */
export function resolvePageRequest(
  params: PageRequestParams = {},
): ResolvedPageRequest {
  const { defaultPageSize, maxPageSize } = MACHINE_IDENTITY_CONFIG.list;

  const requestedPage = Number.isFinite(params.page)
    ? Math.trunc(params.page as number)
    : 0;
  const requestedSize = Number.isFinite(params.size)
    ? Math.trunc(params.size as number)
    : defaultPageSize;

  const resolved: ResolvedPageRequest = {
    page: Math.max(0, requestedPage),
    size: Math.min(maxPageSize, Math.max(1, requestedSize)),
    direction: params.direction === "asc" ? "asc" : "desc",
  };
  if (params.sort) {
    resolved.sort = params.sort;
  }
  return resolved;
}

/**
 * Drops `undefined`, `null`, and blank-string entries so query keys and request
 * params only ever carry filters the user actually set.
 *
 * <p>Deliberately does not trim: a filter value is passed through verbatim
 * because only the caller knows whether whitespace is noise. Search terms are
 * trimmed by their own resolver, where a leading space is never meaningful.
 */
export function compactParams<T extends Record<string, unknown>>(params: T): T {
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => {
      if (value === undefined || value === null) return false;
      if (typeof value === "string") return value.trim().length > 0;
      return true;
    }),
  ) as T;
}
