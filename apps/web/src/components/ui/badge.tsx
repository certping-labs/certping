// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-medium leading-5 transition-[background-color,border-color,color] duration-150",
  {
    variants: {
      variant: {
        default: "",
        secondary: "",
        success: "",
        warning: "",
        info: "",
        destructive: "",
        outline: "",
        graph: "border-transparent bg-transparent px-0 text-muted-foreground",
      },
      appearance: {
        soft: "",
        text: "border-transparent bg-transparent px-0 py-0 shadow-none",
      },
    },
    compoundVariants: [
      {
        variant: "default",
        appearance: "soft",
        class: "border-transparent bg-secondary text-foreground",
      },
      {
        variant: "default",
        appearance: "text",
        class: "text-foreground",
      },
      {
        variant: "secondary",
        appearance: "soft",
        class: "border-transparent bg-secondary text-muted-foreground",
      },
      {
        variant: "secondary",
        appearance: "text",
        class: "text-muted-foreground",
      },
      {
        variant: "success",
        appearance: "soft",
        class: "border-transparent bg-success-soft text-success-foreground",
      },
      {
        variant: "success",
        appearance: "text",
        class: "text-success-foreground",
      },
      {
        variant: "warning",
        appearance: "soft",
        class: "border-transparent bg-warning-soft text-warning-foreground",
      },
      {
        variant: "warning",
        appearance: "text",
        class: "text-warning-foreground",
      },
      {
        variant: "info",
        appearance: "soft",
        class: "border-transparent bg-info-soft text-info-foreground",
      },
      {
        variant: "info",
        appearance: "text",
        class: "text-primary",
      },
      {
        variant: "destructive",
        appearance: "soft",
        class: "border-transparent bg-danger-soft text-danger-foreground",
      },
      {
        variant: "destructive",
        appearance: "text",
        class: "text-destructive",
      },
      {
        variant: "outline",
        appearance: "soft",
        class: "border-border bg-transparent text-foreground",
      },
      {
        variant: "outline",
        appearance: "text",
        class: "text-foreground",
      },
    ],
    defaultVariants: {
      variant: "default",
      appearance: "soft",
    },
  },
);

export interface BadgeProps
  extends
    React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {
  count?: string;
  includeDot?: boolean;
  textOnly?: boolean;
  subVariants?:
    | "success"
    | "warning"
    | "info"
    | "default"
    | "secondary"
    | "destructive"
    | "outline";
}

function Badge({
  className,
  count,
  includeDot,
  subVariants,
  textOnly = false,
  appearance: appearanceProp,
  variant,
  children,
  ...props
}: BadgeProps) {
  const appearance = textOnly ? "text" : (appearanceProp ?? "soft");

  const dotClassName = cn(
    "inline-block h-1.5 w-1.5 rounded-full",
    subVariants === "success"
      ? "bg-success"
      : subVariants === "warning"
        ? "bg-warning"
        : subVariants === "destructive"
          ? "bg-destructive"
          : "bg-muted-foreground",
  );

  return (
    <div
      className={cn(
        badgeVariants({ variant, appearance }),
        textOnly &&
          "rounded-none border-none px-0 text-sm leading-4 font-medium",
        className,
      )}
      {...props}
    >
      {includeDot ? <span className={dotClassName} /> : null}
      {children}
      {count ? (
        <span
          className={cn(
            "ml-0.5 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-muted px-1 text-2xs font-semibold text-foreground tabular-nums",
            variant === "destructive" &&
              "bg-danger-soft text-danger-foreground",
            variant === "warning" && "bg-warning-soft text-warning-foreground",
            variant === "success" && "bg-success-soft text-success-foreground",
          )}
        >
          {count}
        </span>
      ) : null}
    </div>
  );
}

export { Badge, badgeVariants };
