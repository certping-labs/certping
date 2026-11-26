// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { type ReactNode } from "react";

import { cn } from "@/lib/utils";

interface FeatureStatePanelProps {
  /** Decorative mark; the heading carries the meaning. */
  icon: ReactNode;
  /** Colour class for the icon tile. */
  iconClassName?: string;
  title: ReactNode;
  body: ReactNode;
  actions?: ReactNode;
  /** `page` fills the workspace pane; `inline` replaces one region of a page. */
  variant?: "page" | "inline";
  /** `alert` announces the state at once (a failure the user can retry). */
  role?: "alert";
  className?: string;
}

/**
 * The shared shell of a feature's not-available, needs-organization and
 * failed-to-check states. Always a labelled `<section>`, never a `<main>`:
 * it renders inside the workspace pane, which is the page's `<main>`.
 */
export function FeatureStatePanel({
  icon,
  iconClassName = "text-muted-foreground",
  title,
  body,
  actions,
  variant = "page",
  role,
  className,
}: FeatureStatePanelProps) {
  const titleId = React.useId();
  const isPage = variant === "page";
  const Heading = isPage ? "h1" : "h2";

  const panel = (
    <section
      aria-labelledby={titleId}
      role={role}
      data-slot="card"
      className={cn(
        "mx-auto flex w-full max-w-lg flex-col items-start gap-4 rounded-xl border border-border bg-card p-6 text-card-foreground sm:p-8",
        !isPage && className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "flex size-10 items-center justify-center rounded-[10px] bg-secondary",
          iconClassName,
        )}
      >
        {icon}
      </span>
      <div className="space-y-1.5">
        <Heading
          id={titleId}
          className={cn(
            "font-semibold tracking-[-0.015em] text-foreground",
            isPage ? "text-2xl" : "text-[15px] leading-6",
          )}
        >
          {title}
        </Heading>
        <p className="text-sm leading-6 text-muted-foreground">{body}</p>
      </div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-2 pt-1">{actions}</div>
      ) : null}
    </section>
  );

  if (!isPage) return panel;

  return (
    <div className={cn("flex-1 px-4 py-10 sm:px-6 md:py-16", className)}>
      {panel}
    </div>
  );
}
