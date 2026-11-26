// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import {
  CaretLeftIcon,
  CaretRightIcon,
  CaretDoubleLeftIcon,
} from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { AuditTrailListCopy } from "@/lib/audit-trail-source";

// The audit trails serve at most 100 rows a page.
export const AUDIT_TRAIL_PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;

const moreThan = (count: string, rows: string) => `More than ${count} ${rows}`;

/**
 * "25 events"; when the server stopped counting, the source's capped format
 * ("10,000+ events"), else "More than 10,000 events".
 */
export const auditTrailTotalLabel = (
  page: { totalElements: number; totalCapped: boolean },
  { one, other }: AuditTrailListCopy["total"],
  capped: AuditTrailListCopy["totalCapped"] = moreThan,
): string => {
  const count = page.totalElements.toLocaleString();
  const rows = page.totalElements === 1 ? one : other;
  return page.totalCapped ? capped(count, other) : `${count} ${rows}`;
};

interface AuditTrailPaginationProps {
  readonly totalLabel: string;
  readonly page: number;
  readonly totalPages: number;
  /** `totalPages` is a lower bound: "Page 2 of 400+". */
  readonly totalCapped?: boolean;
  readonly pageSize: number;
  readonly canGoNext: boolean;
  readonly disabled: boolean;
  readonly onFirstPage: () => void;
  readonly onPreviousPage: () => void;
  readonly onNextPage: () => void;
  readonly onPageSizeChange: (size: number) => void;
}

/**
 * Paging for a keyset-paged list: first, previous and next only, because a
 * page can be reached only through the one before it.
 */
export function AuditTrailPagination({
  totalLabel,
  page,
  totalPages,
  totalCapped = false,
  pageSize,
  canGoNext,
  disabled,
  onFirstPage,
  onPreviousPage,
  onNextPage,
  onPageSizeChange,
}: AuditTrailPaginationProps) {
  const isFirstPage = page === 0;
  const buttons = [
    {
      label: "Go to first page",
      Icon: CaretDoubleLeftIcon,
      onClick: onFirstPage,
      isDisabled: isFirstPage,
    },
    {
      label: "Go to previous page",
      Icon: CaretLeftIcon,
      onClick: onPreviousPage,
      isDisabled: isFirstPage,
    },
    {
      label: "Go to next page",
      Icon: CaretRightIcon,
      onClick: onNextPage,
      isDisabled: !canGoNext,
    },
  ];

  return (
    <div className="flex flex-col gap-3 border-t bg-card-background p-4 sm:flex-row sm:items-center sm:justify-between">
      <p className="text-sm text-muted-foreground">{totalLabel}</p>
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
              {AUDIT_TRAIL_PAGE_SIZE_OPTIONS.map((option) => (
                <SelectItem key={option} value={`${option}`}>
                  {option}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="text-sm font-medium">
          Page {(page + 1).toLocaleString()} of{" "}
          {Math.max(1, totalPages, page + 1).toLocaleString()}
          {totalCapped ? "+" : ""}
        </div>

        <div className="flex items-center gap-1">
          {buttons.map(({ label, Icon, onClick, isDisabled }) => (
            <Button
              key={label}
              type="button"
              variant="icon"
              size="icon"
              className="h-8 w-8 p-0"
              disabled={disabled || isDisabled}
              onClick={onClick}
            >
              <span className="sr-only">{label}</span>
              <Icon className="h-4 w-4" />
            </Button>
          ))}
        </div>
      </div>
    </div>
  );
}
