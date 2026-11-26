// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared server-pagination envelope.
 *
 * <p>The backend is Spring Data-backed, so every paginated collection is
 * serialized in this shape with a ZERO-BASED {@code number}. The shared
 * {@code ServerPagination} control speaks the same zero-based contract.
 */
export interface SpringPage<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  size: number;
  number: number;
  numberOfElements: number;
  first: boolean;
  last: boolean;
  empty: boolean;
  pageable: {
    pageNumber: number;
    pageSize: number;
    offset: number;
    paged: boolean;
    unpaged: boolean;
  };
  sort: {
    empty: boolean;
    sorted: boolean;
    unsorted: boolean;
  };
}

/** Zero-based page request common to every paginated list endpoint. */
export interface PageRequestParams {
  page?: number;
  size?: number;
  sort?: string;
  direction?: SortDirection;
}

export type SortDirection = "asc" | "desc";
