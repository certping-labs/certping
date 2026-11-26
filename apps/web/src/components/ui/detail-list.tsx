// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import * as React from "react";

import { cn } from "@/lib/utils";

export function DetailList({
  className,
  ...props
}: React.HTMLAttributes<HTMLDListElement>) {
  return (
    <dl
      className={cn(
        "grid grid-cols-1 gap-y-3 sm:grid-cols-[minmax(7rem,11rem)_minmax(0,1fr)] sm:gap-x-6 sm:gap-y-2.5",
        className,
      )}
      {...props}
    />
  );
}

export function DetailItem({
  label,
  children,
  mono = false,
  className,
}: {
  label: React.ReactNode;
  children?: React.ReactNode;
  mono?: boolean;
  className?: string;
}) {
  const empty =
    children === null ||
    children === undefined ||
    children === "" ||
    children === false;
  return (
    <div className={cn("contents", className)}>
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd
        className={cn(
          "min-w-0 text-sm wrap-break-word text-foreground",
          mono && "font-mono text-[13px] break-all",
          empty && "text-muted-foreground",
        )}
      >
        {empty ? "-" : children}
      </dd>
    </div>
  );
}

export function DetailSection({
  title,
  description,
  action,
  children,
  className,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  const headingId = React.useId();
  return (
    <section
      aria-labelledby={headingId}
      className={cn(
        "space-y-4 px-5 py-5 [&+&]:border-t [&+&]:border-divider",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 space-y-0.5">
          <h2
            id={headingId}
            className="text-[15px] font-semibold tracking-[-0.015em] text-foreground"
          >
            {title}
          </h2>
          {description ? (
            <p className="text-sm text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
      {children}
    </section>
  );
}
