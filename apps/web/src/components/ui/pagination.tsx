// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import {
  CaretLeftIcon,
  CaretRightIcon,
  CaretDoubleLeftIcon,
  CaretDoubleRightIcon,
} from "@phosphor-icons/react";
import { Table } from "@tanstack/react-table";

import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface DataTablePaginationProps<TData> {
  table: Table<TData>;
}

export function DataTablePagination<TData>({
  table,
}: DataTablePaginationProps<TData>) {
  return (
    <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:items-center sm:gap-4 lg:gap-6">
      <div className="flex items-center justify-between gap-2 sm:justify-start">
        <p className="text-xs font-medium text-muted-foreground">Rows</p>
        <Select
          value={`${table.getState().pagination.pageSize}`}
          onValueChange={(value) => {
            table.setPageSize(Number(value));
          }}
        >
          <SelectTrigger className="h-8 w-[72px]">
            <SelectValue placeholder={table.getState().pagination.pageSize} />
          </SelectTrigger>
          <SelectContent side="top">
            {[10, 20, 30, 40, 50].map((pageSize) => (
              <SelectItem key={pageSize} value={`${pageSize}`}>
                {pageSize}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="flex min-w-[118px] items-center justify-start text-sm font-medium text-foreground sm:justify-center">
        Page {table.getState().pagination.pageIndex + 1} of{" "}
        {table.getPageCount()}
      </div>
      <div className="flex items-center justify-between gap-1.5 sm:justify-start">
        <Button
          variant="outline"
          size={"iconSm"}
          className="hidden h-8 w-8 rounded-[10px] p-0 lg:flex"
          onClick={() => table.setPageIndex(0)}
          disabled={!table.getCanPreviousPage()}
        >
          <span className="sr-only">Go to first page</span>
          <CaretDoubleLeftIcon className="h-4 w-4" />
        </Button>
        <Button
          variant="outline"
          size={"iconSm"}
          className="h-8 w-8 rounded-[10px] p-0"
          onClick={() => table.previousPage()}
          disabled={!table.getCanPreviousPage()}
        >
          <span className="sr-only">Go to previous page</span>
          <CaretLeftIcon className="h-4 w-4" />
        </Button>
        <Button
          variant="outline"
          size={"iconSm"}
          className="h-8 w-8 rounded-[10px] p-0"
          onClick={() => table.nextPage()}
          disabled={!table.getCanNextPage()}
        >
          <span className="sr-only">Go to next page</span>
          <CaretRightIcon className="h-4 w-4" />
        </Button>
        <Button
          variant="outline"
          size={"iconSm"}
          className="hidden h-8 w-8 rounded-[10px] p-0 lg:flex"
          onClick={() => table.setPageIndex(table.getPageCount() - 1)}
          disabled={!table.getCanNextPage()}
        >
          <span className="sr-only">Go to last page</span>
          <CaretDoubleRightIcon className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
