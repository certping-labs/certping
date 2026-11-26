// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";

import { cn } from "@/lib/utils";

const Checkbox = React.forwardRef<
  React.ElementRef<typeof CheckboxPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof CheckboxPrimitive.Root>
>(({ className, ...props }, ref) => (
  <CheckboxPrimitive.Root
    ref={ref}
    className={cn(
      "group peer grid h-[18px] w-[18px] shrink-0 place-items-center rounded-lg border border-muted-foreground bg-[hsl(var(--control-bg))] transition-[background-color,border-color,transform] duration-150 ease-out-soft hover:border-primary focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden active:scale-90 disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-primary data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground data-[state=indeterminate]:border-primary data-[state=indeterminate]:bg-primary data-[state=indeterminate]:text-primary-foreground motion-reduce:active:scale-100",
      className,
    )}
    {...props}
  >
    <CheckboxPrimitive.Indicator className="flex items-center justify-center text-current">
      <svg
        viewBox="0 0 12 12"
        fill="none"
        aria-hidden
        className="h-3 w-3 group-data-[state=indeterminate]:hidden"
      >
        <path
          d="M2.5 6.25 5 8.75l4.5-5.5"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="animate-[checkbox-draw_220ms_var(--ease-out-soft)_both] [stroke-dasharray:12] motion-reduce:animate-none"
        />
      </svg>
      <svg
        viewBox="0 0 12 12"
        fill="none"
        aria-hidden
        className="hidden h-3 w-3 group-data-[state=indeterminate]:block"
      >
        <path
          d="M3 6h6"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
        />
      </svg>
    </CheckboxPrimitive.Indicator>
  </CheckboxPrimitive.Root>
));
Checkbox.displayName = CheckboxPrimitive.Root.displayName;

export { Checkbox };
