// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { type MouseEvent } from "react";
import { CheckIcon, CopyIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { middleEllipsis } from "@/lib/middle-ellipsis";
import { cn } from "@/lib/utils";

const COPIED_MS = 1_500;

interface AuditTrailCopyIdProps {
  /** What the id is, lowercase, e.g. "request ID". */
  label: string;
  value: string;
  /**
   * `truncate` (a table cell): one line, shortened from the middle and
   * clipped to the cell, the whole id on hover. `wrap` (a details field): the
   * whole id, broken anywhere to fit, the button after it.
   */
  layout?: "truncate" | "wrap";
  className?: string;
}

/**
 * An id support asks for, with a button that copies it, always in full.
 * Inside a clickable row, so a click on the button does not open the row too.
 */
export function AuditTrailCopyId({
  label,
  value,
  layout = "truncate",
  className,
}: AuditTrailCopyIdProps) {
  const [copied, setCopied] = React.useState(false);

  React.useEffect(() => {
    if (!copied) {
      return undefined;
    }
    const timer = setTimeout(() => setCopied(false), COPIED_MS);
    return () => clearTimeout(timer);
  }, [copied]);

  const copy = (event: MouseEvent) => {
    event.stopPropagation();
    navigator.clipboard.writeText(value).then(
      () => {
        setCopied(true);
        toast.success(`Copied the ${label}`, { id: "audit-trail-copy-id" });
      },
      () =>
        toast.error(`Couldn't copy the ${label}. Select it and copy it.`, {
          id: "audit-trail-copy-id",
        }),
    );
  };

  const button = (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className="h-9 w-9 shrink-0 align-middle sm:h-7 sm:w-7"
      aria-label={`Copy ${label} ${value}`}
      title={`Copy ${label}`}
      onClick={copy}
    >
      {copied ? (
        <CheckIcon className="h-3.5 w-3.5" aria-hidden />
      ) : (
        <CopyIcon className="h-3.5 w-3.5" aria-hidden />
      )}
    </Button>
  );

  if (layout === "wrap") {
    return (
      <span className={cn("block min-w-0", className)}>
        <span className="font-mono text-[13px] break-all text-foreground">
          {value}
        </span>{" "}
        {button}
      </span>
    );
  }
  return (
    <span className={cn("flex w-full min-w-0 items-center gap-1", className)}>
      <span
        className="min-w-0 truncate font-mono text-[13px] text-foreground"
        title={value}
      >
        {middleEllipsis(value)}
      </span>
      {button}
    </span>
  );
}
