// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  CaretLeftIcon,
  CaretRightIcon,
  CaretDoubleLeftIcon,
  CaretDoubleRightIcon,
} from "@phosphor-icons/react/dist/ssr";

import { Button } from "@/components/ui/button";

interface ServerPaginationNavigationProps {
  readonly page: number;
  readonly totalPages: number;
  readonly disabled: boolean;
  readonly onPageChange: (page: number) => void;
}

/** Renders first, previous, next, and last-page controls. */
export function ServerPaginationNavigation({
  page,
  totalPages,
  disabled,
  onPageChange,
}: ServerPaginationNavigationProps) {
  const isFirstPage = page === 0;
  const isLastPage = page === totalPages - 1;
  const navigationButtons = [
    {
      label: "Go to first page",
      Icon: CaretDoubleLeftIcon,
      targetPage: 0,
      isBoundary: isFirstPage,
      isResponsive: true,
    },
    {
      label: "Go to previous page",
      Icon: CaretLeftIcon,
      targetPage: Math.max(0, page - 1),
      isBoundary: isFirstPage,
      isResponsive: false,
    },
    {
      label: "Go to next page",
      Icon: CaretRightIcon,
      targetPage: Math.min(totalPages - 1, page + 1),
      isBoundary: isLastPage,
      isResponsive: false,
    },
    {
      label: "Go to last page",
      Icon: CaretDoubleRightIcon,
      targetPage: totalPages - 1,
      isBoundary: isLastPage,
      isResponsive: true,
    },
  ];

  return (
    <div className="flex items-center gap-1">
      {navigationButtons.map(
        ({ label, Icon, targetPage, isBoundary, isResponsive }) => (
          <Button
            key={label}
            type="button"
            variant="icon"
            size="icon"
            className={
              isResponsive ? "hidden h-8 w-8 p-0 lg:flex" : "h-8 w-8 p-0"
            }
            onClick={() => onPageChange(targetPage)}
            disabled={disabled || isBoundary}
          >
            <span className="sr-only">{label}</span>
            <Icon className="h-4 w-4" />
          </Button>
        ),
      )}
    </div>
  );
}
