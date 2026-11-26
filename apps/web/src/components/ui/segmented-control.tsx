// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";

import { useSlidingThumb } from "@/hooks/use-sliding-thumb";
import { cn } from "@/lib/utils";

export interface SegmentedOption<T extends string> {
  value: T;
  label: React.ReactNode;
  adornment?: React.ReactNode;
}

interface SegmentedControlProps<T extends string> {
  value: T;
  onValueChange: (value: T) => void;
  options: readonly SegmentedOption<T>[];
  "aria-label": string;
  className?: string;
}

export function SegmentedControl<T extends string>({
  value,
  onValueChange,
  options,
  className,
  "aria-label": ariaLabel,
}: SegmentedControlProps<T>) {
  const { itemRef, moving, thumbStyle } = useSlidingThumb(
    options.findIndex((option) => option.value === value),
  );
  return (
    <div
      aria-label={ariaLabel}
      className={cn(
        "mg-segmented inline-flex h-10 items-center gap-0.5 rounded-full p-1",
        className,
      )}
      role="group"
    >
      <span
        aria-hidden
        className={cn("mg-thumb", moving && "is-moving")}
        style={thumbStyle}
      />
      {options.map((option, index) => {
        const selected = option.value === value;
        return (
          <button
            aria-pressed={selected}
            className={cn(
              "relative inline-flex h-full items-center gap-1.5 rounded-full px-3.5 text-sm font-medium tracking-[-0.01em] focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden",
              selected
                ? "text-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
            key={option.value}
            onClick={() => onValueChange(option.value)}
            ref={itemRef(index)}
            type="button"
          >
            {option.label}
            {option.adornment}
          </button>
        );
      })}
    </div>
  );
}
