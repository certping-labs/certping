// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { ArrowUpRightIcon } from "@phosphor-icons/react/dist/ssr";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import { cn } from "@/lib/utils";

export type TopActionTone = "danger" | "neutral" | "success" | "warning";

interface TopActionTileProps {
  description: string;
  icon: PhosphorIcon;
  label: string;
  onClick: () => void;
  tone: TopActionTone;
  value: number;
}

const TONE_STYLES: Record<TopActionTone, { icon: string; surface: string }> = {
  danger: {
    icon: "text-danger-foreground",
    surface: "border-danger-border bg-danger-soft",
  },
  neutral: {
    icon: "text-muted-foreground",
    surface: "border-border bg-muted/60",
  },
  success: {
    icon: "text-success-foreground",
    surface: "border-success-border bg-success-soft",
  },
  warning: {
    icon: "status-warning-text",
    surface: "border-warning-border bg-warning-soft",
  },
};

export function TopActionTile({
  description,
  icon: Icon,
  label,
  onClick,
  tone,
  value,
}: TopActionTileProps) {
  const toneStyles = TONE_STYLES[tone];

  return (
    <button
      type="button"
      className="group flex min-h-36 w-full flex-col items-start bg-card p-4 text-left transition-colors hover:bg-muted/35 focus-visible:z-10 focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-hidden focus-visible:ring-inset sm:p-5"
      onClick={onClick}
    >
      <div className="flex w-full items-start justify-between gap-4">
        <span
          className={cn(
            "flex size-9 items-center justify-center rounded-md border",
            toneStyles.surface,
          )}
        >
          <Icon aria-hidden="true" className={cn("size-4", toneStyles.icon)} />
        </span>
        <span className="text-2xl leading-none font-semibold tracking-tight text-foreground tabular-nums">
          {value.toLocaleString()}
        </span>
      </div>
      <span className="mt-4 text-sm font-medium text-foreground">{label}</span>
      <span className="mt-1 text-xs leading-4 text-muted-foreground">
        {description}
      </span>
      <span className="mt-auto flex items-center gap-1 pt-4 text-xs font-medium text-primary">
        Review certificates
        <ArrowUpRightIcon
          aria-hidden="true"
          className="size-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
        />
      </span>
    </button>
  );
}
