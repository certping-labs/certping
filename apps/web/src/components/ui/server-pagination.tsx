// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ServerPaginationNavigation } from "@/components/ui/server-pagination-navigation";

export interface ServerPaginationProps {
  readonly page: number;
  readonly totalPages: number;
  readonly pageSize: number;
  readonly totalElements: number;
  /**
   * The backend stopped counting: `totalElements` (and so `totalPages`) is a
   * lower bound, shown as "10,000+" and "400+".
   */
  readonly totalCapped?: boolean;
  readonly disabled?: boolean;
  readonly pageSizeOptions?: readonly number[];
  readonly onPageChange: (page: number) => void;
  readonly onPageSizeChange: (size: number) => void;
}

const PAGE_SIZE_OPTIONS = [10, 20, 25, 30, 40, 50, 100, 200];
const MAX_PAGE_OPTIONS = 30;
const PAGE_OPTION_RADIUS = 10;

function getPageOptions(currentPage: number, totalPages: number): number[] {
  const safeTotalPages = Math.max(1, totalPages);
  if (safeTotalPages <= MAX_PAGE_OPTIONS) {
    return Array.from({ length: safeTotalPages }, (_, index) => index);
  }

  const start = Math.max(0, currentPage - PAGE_OPTION_RADIUS);
  const end = Math.min(safeTotalPages - 1, currentPage + PAGE_OPTION_RADIUS);
  const pages = new Set<number>([0, safeTotalPages - 1]);

  for (let current = start; current <= end; current += 1) {
    pages.add(current);
  }

  return Array.from(pages).sort((left, right) => left - right);
}

/**
 * Renders controls for a server-paginated collection.
 * Page values passed to and emitted by this component are zero-based.
 */
export function ServerPagination({
  page,
  totalPages,
  pageSize,
  totalElements,
  totalCapped = false,
  disabled = false,
  pageSizeOptions = PAGE_SIZE_OPTIONS,
  onPageChange,
  onPageSizeChange,
}: ServerPaginationProps) {
  const safeTotalPages = Math.max(1, totalPages);
  const normalizedPage = Math.min(Math.max(0, page), safeTotalPages - 1);
  const firstVisibleEntry =
    totalElements === 0 ? 0 : normalizedPage * pageSize + 1;
  const lastVisibleEntry = Math.min(
    totalElements,
    (normalizedPage + 1) * pageSize,
  );
  return (
    <div className="flex flex-col gap-3 border-t border-divider px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="text-sm text-muted-foreground">
        Showing {firstVisibleEntry.toLocaleString()} to{" "}
        {lastVisibleEntry.toLocaleString()} of {totalElements.toLocaleString()}
        {totalCapped ? "+" : ""} entries
      </div>

      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <p className="text-sm font-medium">Rows per page</p>
          <Select
            value={`${pageSize}`}
            onValueChange={(value) => onPageSizeChange(Number(value))}
            disabled={disabled}
          >
            <SelectTrigger aria-label="Rows per page" className="h-8 w-[76px]">
              <SelectValue placeholder={pageSize} />
            </SelectTrigger>
            <SelectContent side="top">
              {pageSizeOptions.map((option) => (
                <SelectItem key={option} value={`${option}`}>
                  {option}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="text-sm font-medium">
          Page {normalizedPage + 1} of {safeTotalPages}
          {totalCapped ? "+" : ""}
        </div>

        <div className="flex items-center gap-2">
          <p className="text-sm font-medium">Go to page</p>
          <Select
            value={`${normalizedPage}`}
            onValueChange={(value) => onPageChange(Number(value))}
            disabled={disabled}
          >
            <SelectTrigger aria-label="Go to page" className="h-8 w-[86px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent side="top">
              {getPageOptions(normalizedPage, safeTotalPages).map((option) => (
                <SelectItem key={option} value={`${option}`}>
                  {option + 1}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <ServerPaginationNavigation
          page={normalizedPage}
          totalPages={safeTotalPages}
          disabled={disabled}
          onPageChange={onPageChange}
        />
      </div>
    </div>
  );
}
