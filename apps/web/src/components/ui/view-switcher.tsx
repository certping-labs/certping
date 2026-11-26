// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import { SquaresFourIcon, TableIcon } from "@phosphor-icons/react";

import { useSlidingThumb } from "@/hooks/use-sliding-thumb";
import { cn } from "@/lib/utils";

export type ViewMode = "table" | "card";

interface ViewSwitcherProps {
  value: ViewMode;
  onValueChange: (value: ViewMode) => void;
  className?: string;
  disabled?: boolean;
  size?: "sm" | "md" | "lg";
  showLabels?: boolean;
}

const sizeVariants = {
  sm: {
    container: "h-8 p-0.5",
    indicator: "inset-y-0.5",
    button: "h-7 px-2.5 text-xs",
    icon: "size-3.5",
  },
  md: {
    container: "h-10 p-1",
    indicator: "inset-y-1",
    button: "h-8 px-3 text-sm",
    icon: "size-4",
  },
  lg: {
    container: "h-12 p-1",
    indicator: "inset-y-1",
    button: "h-10 px-4 text-base",
    icon: "size-5",
  },
} as const;

const OPTIONS = [
  { value: "table", icon: TableIcon, label: "Table" },
  { value: "card", icon: SquaresFourIcon, label: "Grid" },
] as const;

const ViewSwitcher = React.forwardRef<HTMLDivElement, ViewSwitcherProps>(
  (
    {
      value,
      onValueChange,
      className,
      disabled = false,
      size = "md",
      showLabels = true,
    },
    ref,
  ) => {
    const variants = sizeVariants[size];
    const { itemRef, moving, thumbStyle } = useSlidingThumb(
      OPTIONS.findIndex((option) => option.value === value),
    );
    return (
      <div
        ref={ref}
        role="group"
        aria-label="View"
        className={cn(
          "mg-segmented relative inline-grid shrink-0 grid-cols-2 items-center rounded-full",
          variants.container,
          disabled && "pointer-events-none opacity-50",
          className,
        )}
      >
        <span
          aria-hidden
          className={cn("mg-thumb", variants.indicator, moving && "is-moving")}
          style={thumbStyle}
        />
        {OPTIONS.map(({ value: option, icon: Icon, label }, index) => {
          const isActive = value === option;
          return (
            <button
              key={option}
              type="button"
              aria-pressed={isActive}
              aria-label={showLabels ? undefined : label}
              disabled={disabled}
              onClick={() => onValueChange(option)}
              ref={itemRef(index)}
              className={cn(
                "relative inline-flex items-center justify-center gap-1.5 rounded-full font-medium transition-colors duration-200 focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden",
                variants.button,
                isActive
                  ? "text-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon aria-hidden className={variants.icon} />
              {showLabels ? label : null}
            </button>
          );
        })}
      </div>
    );
  },
);

ViewSwitcher.displayName = "ViewSwitcher";

export { ViewSwitcher };
