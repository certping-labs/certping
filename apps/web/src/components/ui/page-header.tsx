// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { ArrowLeftIcon, CaretRightIcon, InfoIcon } from "@phosphor-icons/react";
import Link from "next/link";
import React, { type ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { BadgeProps } from "@/components/ui/badge";

interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface PageHeaderProps {
  title: string;
  breadcrumbs?: BreadcrumbItem[];
  subtitle?: ReactNode;
  backHref?: string;
  actions?: ReactNode;
  /** What the page is for and what is done there, one short line each, behind an info icon. */
  info?: readonly string[];
  badge?: {
    label: string;
    variant?: BadgeProps["variant"];
    textOnly?: boolean;
    className?: string;
  };
  level?: "page" | "section";
  className?: string;
}

export function PageHeader({
  title,
  breadcrumbs = [],
  subtitle,
  backHref,
  actions,
  info,
  badge,
  level = "page",
  className,
}: PageHeaderProps) {
  const Heading = level === "page" ? "h1" : "h2";
  const showBack = Boolean(backHref) && breadcrumbs.length === 0;

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {breadcrumbs.length > 0 ? (
        <nav aria-label="Breadcrumb">
          <ol className="flex flex-wrap items-center gap-1 text-sm text-muted-foreground">
            {breadcrumbs.map((breadcrumb, index) => (
              <li
                key={`${breadcrumb.label}-${index}`}
                className="flex items-center gap-1"
              >
                {breadcrumb.href ? (
                  <Link
                    href={breadcrumb.href}
                    className="rounded-md transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
                  >
                    {breadcrumb.label}
                  </Link>
                ) : (
                  <span>{breadcrumb.label}</span>
                )}
                <CaretRightIcon
                  className="size-3.5 text-muted-foreground/70"
                  aria-hidden
                />
              </li>
            ))}
            <li aria-current="page" className="truncate text-foreground">
              {title}
            </li>
          </ol>
        </nav>
      ) : null}

      <div className="flex flex-col gap-3 md:items-start md:justify-between lg:flex-row">
        <div className="flex min-w-0 items-start gap-2">
          {showBack ? (
            <Link
              href={backHref as string}
              aria-label="Back"
              className="mt-0.5 -ml-1.5 inline-flex size-8 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-[background-color,color,transform] duration-150 hover:bg-secondary hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden active:scale-95 [&:hover>svg]:-translate-x-0.5"
            >
              <ArrowLeftIcon
                className="size-4 transition-transform duration-150"
                aria-hidden
              />
            </Link>
          ) : null}
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <Heading
                className={cn(
                  "font-semibold text-foreground",
                  level === "page"
                    ? "text-2xl tracking-[-0.03em]"
                    : "text-lg tracking-[-0.02em]",
                )}
              >
                {title}
              </Heading>
              {info?.length ? <PageInfo title={title} lines={info} /> : null}
              {badge ? (
                <Badge
                  variant={badge.variant || "secondary"}
                  textOnly={badge.textOnly}
                  className={cn("font-medium", badge.className)}
                >
                  {badge.label}
                </Badge>
              ) : null}
            </div>
            {subtitle ? (
              <div className="max-w-3xl text-sm leading-5 text-muted-foreground">
                {subtitle}
              </div>
            ) : null}
          </div>
        </div>
        {actions && (
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        )}
      </div>
    </div>
  );
}

function PageInfo({
  title,
  lines,
}: {
  title: string;
  lines: readonly string[];
}) {
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            aria-label={`About ${title}`}
            className="inline-flex size-6 items-center justify-center rounded-full text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
          >
            <InfoIcon className="size-4" aria-hidden />
          </button>
        </TooltipTrigger>
        <TooltipContent
          side="bottom"
          align="start"
          className="max-w-sm space-y-2 text-sm leading-5"
        >
          {lines.map((line) => (
            <p key={line}>{line}</p>
          ))}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
