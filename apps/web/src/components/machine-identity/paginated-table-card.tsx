// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { ColumnDef } from "@tanstack/react-table";

import { CustomTable } from "@/components/ui/custom-table";
import { MachineIdentityQueryErrorState } from "@/components/machine-identity/query-error-state";
import { MACHINE_IDENTITY_PAGE_SIZES } from "@/lib/machine-identity/config";
import type { SpringPage } from "@/types/pagination";

interface PaginatedTableCardProps<T extends object> {
  /** TanStack column definitions; give each column a readable `id`. */
  columns: ColumnDef<T>[];
  page: SpringPage<T> | undefined;
  /**
   * Pass the query's `isPending`, not `isLoading`: a query held back by
   * `enabled` has no data and no in-flight request, and `isLoading` reports
   * false for it - which would flash "no results" before the request is even
   * allowed to start.
   */
  isLoading: boolean;
  isFetching: boolean;
  error: unknown;
  errorTitle: string;
  errorDescription: string;
  emptyMessage: string;
  /**
   * Filter controls for this list. Rendered on the same row as the table's own
   * column-visibility menu: as separate blocks they produced a filter bar and
   * then a near-empty row holding one right-aligned button.
   */
  toolbar?: React.ReactNode;
  /** Wired to the query's `refetch` so a failed page can be retried in place. */
  onRetry?: () => void;
  isRetrying?: boolean;
  /** Stable row identity, so selection and keys survive refetches. */
  getRowId: (row: T) => string;
  /** Minimum table width before horizontal scrolling kicks in. */
  minWidthClassName?: string;
  /** Column ids hidden until the viewer enables them via the Columns menu. */
  defaultHiddenColumns?: string[];
  onRowClick?: (row: T) => void;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
}

/**
 * Server-paginated {@link CustomTable} shell shared by every Machine Identity
 * list. Search and filtering happen upstream (URL-synced controls hitting the
 * paginated API), so the table itself only renders the current page: the four
 * states - loading, error, empty, populated - plus the shared pagination
 * footer speaking the zero-based Spring contract.
 */
export function PaginatedTableCard<T extends object>({
  columns,
  page,
  isLoading,
  isFetching,
  error,
  errorTitle,
  errorDescription,
  emptyMessage,
  toolbar,
  onRetry,
  isRetrying,
  getRowId,
  minWidthClassName = "min-w-272",
  defaultHiddenColumns,
  onRowClick,
  onPageChange,
  onPageSizeChange,
}: PaginatedTableCardProps<T>) {
  if (error) {
    return (
      <div className="space-y-4">
        {toolbar}
        <MachineIdentityQueryErrorState
          error={error}
          title={errorTitle}
          description={errorDescription}
          onRetry={onRetry}
          isRetrying={isRetrying}
        />
      </div>
    );
  }

  return (
    <div aria-busy={isFetching}>
      <CustomTable<T, unknown>
        columns={columns}
        data={page?.content ?? []}
        isLoading={isLoading}
        emptyTableMsg={emptyMessage}
        getRowId={getRowId}
        onRowClick={onRowClick}
        defaultHiddenColumns={defaultHiddenColumns}
        manualFiltering
        toolbarLeading={
          toolbar ? <div className="min-w-0 flex-1">{toolbar}</div> : undefined
        }
        showColumnVisibility
        // No footer until the first page arrives; the server footer takes over.
        showPagination={Boolean(page)}
        tableClassName="rounded-lg border border-border"
        tableElementClassName={minWidthClassName}
        serverPagination={
          page
            ? {
                page: page.number,
                totalPages: page.totalPages,
                pageSize: page.size,
                totalElements: page.totalElements,
                disabled: isFetching,
                pageSizeOptions: MACHINE_IDENTITY_PAGE_SIZES,
                onPageChange,
                onPageSizeChange,
              }
            : undefined
        }
      />
    </div>
  );
}
