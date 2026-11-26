// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { cn } from "@/lib/utils";

function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-lg motion-reduce:animate-none",
        className,
      )}
      style={{ backgroundColor: "var(--skeleton-bg, hsl(var(--muted)))" }}
      {...props}
    />
  );
}

export { Skeleton };
