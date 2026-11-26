// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { BETA_INTEGRATION_DESCRIPTION } from "@/lib/integration-maturity";
import { cn } from "@/lib/utils";

/**
 * Small "Beta" label for an integration without a real-target or end-to-end
 * test. It is aria-hidden so it does not change the accessible name of the
 * option it sits in; put {@link BETA_INTEGRATION_DESCRIPTION} in that
 * option's title or description for assistive technology.
 */
export function BetaBadge({ className }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      data-testid="beta-badge"
      title={BETA_INTEGRATION_DESCRIPTION}
      className={cn(
        "inline-flex shrink-0 items-center rounded-full border border-transparent bg-warning-soft px-1.5 text-[10px] leading-4 font-medium tracking-wide text-warning-foreground uppercase",
        className,
      )}
    >
      Beta
    </span>
  );
}
