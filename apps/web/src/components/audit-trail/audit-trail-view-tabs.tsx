// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";

import { useSlidingThumb } from "@/hooks/use-sliding-thumb";
import type { AuditTrailViews } from "@/lib/audit-trail-source";
import { cn } from "@/lib/utils";

/**
 * The logs of one subject, e.g. what changed and who read what. Each is a page
 * of its own, so these are links, with the open one marked. The thumb moves on
 * click, before the next page arrives.
 */
export function AuditTrailViewTabs({
  views,
  view,
}: {
  views: AuditTrailViews;
  view: string;
}) {
  const [pending, setPending] = useState<string | null>(null);
  useEffect(() => setPending(null), [view]);
  const active = pending ?? view;
  const { itemRef, moving, thumbStyle } = useSlidingThumb(
    Math.max(
      0,
      views.items.findIndex((item) => item.id === active),
    ),
  );
  return (
    <nav
      aria-label={views.label}
      className="mg-segmented inline-flex h-10 items-center gap-0.5 rounded-full p-1"
    >
      <span
        aria-hidden
        className={cn("mg-thumb", moving && "is-moving")}
        style={thumbStyle}
      />
      {views.items.map(({ id, label, href }, index) => (
        <Link
          key={id}
          href={href}
          aria-current={id === view ? "page" : undefined}
          onClick={() => setPending(id)}
          ref={itemRef(index)}
          className={cn(
            "relative inline-flex h-8 items-center rounded-full px-3.5 text-sm font-medium tracking-[-0.01em] transition-colors duration-200 focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden",
            id === active
              ? "text-foreground"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {label}
        </Link>
      ))}
    </nav>
  );
}
