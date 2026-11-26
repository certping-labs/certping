// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { DetailBadgeVariant } from "@/components/cert-manager/discovery/discovered-cert-detail-helpers";

export interface DetailItem {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}

export function DetailSection({
  title,
  children,
  description,
  className,
}: {
  title: string;
  children: React.ReactNode;
  description?: string;
  className?: string;
}) {
  return (
    <Card className={cn("border-border bg-card", className)}>
      <CardHeader className="space-y-1.5 pb-3">
        <CardTitle className="text-base font-semibold tracking-[-0.02em]">
          {title}
        </CardTitle>
        {description ? (
          <p className="text-sm leading-5 text-muted-foreground">
            {description}
          </p>
        ) : null}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

export function DetailRows({ items }: { items: DetailItem[] }) {
  return (
    <dl className="divide-y divide-border/70">
      {items.map((item) => (
        <div
          key={item.label}
          className="grid gap-1 py-2.5 sm:grid-cols-[8.5rem_minmax(0,1fr)]"
        >
          <dt className="text-xs font-medium text-muted-foreground">
            {item.label}
          </dt>
          <dd
            className={cn(
              "min-w-0 text-sm leading-5 wrap-break-word whitespace-pre-wrap text-foreground",
              item.mono && "font-mono text-xs break-all",
            )}
          >
            {item.value ?? "-"}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function EmptyDetailText({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-muted-foreground">{children}</p>;
}

export function ValueList({
  values,
  emptyLabel,
  mono = true,
  limit,
}: {
  values: readonly string[];
  emptyLabel: string;
  mono?: boolean;
  limit?: number;
}) {
  const visibleValues = limit ? values.slice(0, limit) : values;
  const hiddenCount = limit ? Math.max(values.length - limit, 0) : 0;

  if (values.length === 0) {
    return <EmptyDetailText>{emptyLabel}</EmptyDetailText>;
  }

  return (
    <div className="flex flex-wrap gap-2">
      {visibleValues.map((value) => (
        <span
          key={value}
          className={cn(
            "max-w-full rounded-lg border border-border bg-secondary px-2.5 py-1 text-xs text-foreground",
            mono && "font-mono break-all",
          )}
        >
          {value}
        </span>
      ))}
      {hiddenCount > 0 ? (
        <Badge variant="secondary">+{hiddenCount} more</Badge>
      ) : null}
    </div>
  );
}

export function StatusBadge({
  children,
  variant,
}: {
  children: React.ReactNode;
  variant: DetailBadgeVariant;
}) {
  return <Badge variant={variant}>{children}</Badge>;
}

export function MetricTile({
  label,
  value,
  description,
  variant = "secondary",
}: {
  label: string;
  value: React.ReactNode;
  description?: string;
  variant?: DetailBadgeVariant;
}) {
  return (
    <div className="rounded-md border border-border bg-background p-3">
      <div className="flex items-start justify-between gap-3">
        <span className="text-xs font-medium text-muted-foreground">
          {label}
        </span>
        <Badge variant={variant} className="shrink-0">
          {value}
        </Badge>
      </div>
      {description ? (
        <p className="mt-2 text-xs leading-5 text-muted-foreground">
          {description}
        </p>
      ) : null}
    </div>
  );
}
