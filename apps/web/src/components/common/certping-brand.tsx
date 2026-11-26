// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Image from "next/image";
import React from "react";

import darkSurfaceSymbol from "@/assets/brand/certping-symbol-color-dark.svg";
import lightSurfaceSymbol from "@/assets/brand/certping-symbol-color-light.svg";
import { cn } from "@/lib/utils";

interface CertPingBrandProps {
  className?: string;
  priority?: boolean;
  surface: "dark" | "light" | "auto";
  symbolClassName?: string;
  wordmarkClassName?: string;
}

/**
 * Renders the official SVG symbol with a scalable live-text wordmark and the registered
 * trademark sign, as on certping.com.
 */
export function CertPingBrand({
  className,
  priority = false,
  surface,
  symbolClassName,
  wordmarkClassName,
}: CertPingBrandProps) {
  return (
    <span className={cn("inline-flex items-center gap-1", className)}>
      {surface === "auto" ? (
        <>
          <Image
            alt="CertPing"
            className={cn("size-8 shrink-0 dark:hidden", symbolClassName)}
            priority={priority}
            src={lightSurfaceSymbol}
          />
          <Image
            alt=""
            aria-hidden
            className={cn("hidden size-8 shrink-0 dark:block", symbolClassName)}
            priority={priority}
            src={darkSurfaceSymbol}
          />
        </>
      ) : (
        <Image
          alt="CertPing"
          className={cn("size-8 shrink-0", symbolClassName)}
          priority={priority}
          src={surface === "dark" ? darkSurfaceSymbol : lightSurfaceSymbol}
        />
      )}
      <span
        className={cn(
          "text-xl leading-none font-[650] tracking-[-0.035em] whitespace-nowrap",
          surface === "dark"
            ? "text-white"
            : surface === "light"
              ? "text-[#0B132B]"
              : "text-foreground",
          wordmarkClassName,
        )}
      >
        CertPing
        <sup
          aria-label="registered trademark"
          className="relative ml-0.5 align-baseline text-[0.65em] leading-none font-semibold"
        >
          &reg;
        </sup>
      </span>
    </span>
  );
}
