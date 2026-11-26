// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React, { type ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface IntegrationsTabHeaderProps {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  /**
   * Marks a category that self-registers from agent health checks. Sets the
   * user's expectation before they go looking for an Add button that this
   * category deliberately does not have.
   */
  autoDiscovered?: boolean;
  className?: string;
}

/**
 * Heading for one Integrations category.
 *
 * A section-level `<h2>` rather than `PageHeader`'s `<h1>` - the section shell
 * above already owns the page's single `<h1>`.
 */
export function IntegrationsTabHeader({
  title,
  description,
  actions,
  autoDiscovered = false,
  className,
}: IntegrationsTabHeaderProps) {
  return (
    <div
      className={cn(
        "flex flex-col gap-3 md:flex-row md:items-start md:justify-between",
        className,
      )}
    >
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold tracking-[-0.02em] text-foreground">
            {title}
          </h2>
          {autoDiscovered ? (
            <Badge variant="secondary" className="font-medium">
              Auto-discovered
            </Badge>
          ) : null}
        </div>
        {description ? (
          <div className="max-w-3xl text-sm leading-5 text-muted-foreground">
            {description}
          </div>
        ) : null}
      </div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      ) : null}
    </div>
  );
}
