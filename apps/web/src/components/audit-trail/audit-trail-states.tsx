// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Link from "next/link";
import {
  WarningCircleIcon,
  ClipboardTextIcon,
  ArrowsClockwiseIcon,
  InfoIcon,
  ScrollIcon,
} from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import type {
  AuditTrailEmptyCopy,
  AuditTrailNotice,
} from "@/lib/audit-trail-source";
import { EXTERNAL_LINK_PROPS, isExternalHref } from "@/lib/support-links";

/** A route this reader cannot use here, e.g. one not deployed yet. */
export function AuditTrailUnavailableState({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <section
      aria-labelledby="audit-trail-unavailable-title"
      className="flex flex-col items-center gap-4 rounded-(--certping-radius-md) border border-dashed border-border bg-card px-6 py-14 text-center"
    >
      <div
        aria-hidden
        className="flex h-12 w-12 items-center justify-center rounded-full bg-secondary text-muted-foreground"
      >
        <ScrollIcon className="h-5 w-5" />
      </div>
      <div className="space-y-1.5">
        <h2
          id="audit-trail-unavailable-title"
          className="text-base font-semibold text-foreground"
        >
          {title}
        </h2>
        <p className="max-w-md text-sm leading-6 text-muted-foreground">
          {description}
        </p>
      </div>
    </section>
  );
}

const NOTICE_LINK_CLASS_NAME =
  "font-medium text-primary underline-offset-4 hover:underline focus-visible:rounded-sm focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background";

/** One quiet line around the list, e.g. how far back it reaches. */
export function AuditTrailNoticeLine({ notice }: { notice: AuditTrailNotice }) {
  const { action } = notice;
  return (
    <p
      role="note"
      className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-sm text-muted-foreground"
    >
      <InfoIcon aria-hidden className="h-4 w-4 shrink-0" />
      <span>{notice.message}</span>
      {action ? (
        <>
          <span aria-hidden>·</span>
          {action.prompt ? <span>{action.prompt}</span> : null}
          {action.href.startsWith("/") ? (
            <Link href={action.href} className={NOTICE_LINK_CLASS_NAME}>
              {action.label}
            </Link>
          ) : (
            // mailto: and https links leave the app, so not through the router.
            <a
              href={action.href}
              className={NOTICE_LINK_CLASS_NAME}
              {...(isExternalHref(action.href) ? EXTERNAL_LINK_PROPS : {})}
            >
              {action.label}
            </a>
          )}
        </>
      ) : null}
    </p>
  );
}

export function AuditTrailEmptyState({
  filtered,
  onClearFilters,
  copy,
}: {
  filtered: boolean;
  onClearFilters: () => void;
  /** What the log holds when it holds nothing. */
  copy: AuditTrailEmptyCopy;
}) {
  return (
    <section
      aria-labelledby="audit-trail-empty-title"
      className="flex flex-col items-center gap-4 rounded-(--certping-radius-md) border border-dashed border-border bg-card px-6 py-14 text-center"
    >
      <div
        aria-hidden
        className="flex h-12 w-12 items-center justify-center rounded-full border border-[hsl(var(--primary)/0.2)] bg-[hsl(var(--primary)/0.08)] text-primary"
      >
        <ClipboardTextIcon className="h-5 w-5" />
      </div>
      <div className="space-y-1.5">
        <h2
          id="audit-trail-empty-title"
          className="text-base font-semibold text-foreground"
        >
          {filtered ? copy.filteredTitle : copy.title}
        </h2>
        <p className="max-w-md text-sm leading-6 text-muted-foreground">
          {filtered
            ? "Try a wider date range or fewer filters."
            : copy.description}
        </p>
      </div>
      {filtered ? (
        <Button variant="outline" onClick={onClearFilters}>
          Clear filters
        </Button>
      ) : null}
    </section>
  );
}

export function AuditTrailErrorState({
  title,
  message,
  retrying,
  onRetry,
}: {
  title: string;
  message: string;
  retrying: boolean;
  onRetry: () => void;
}) {
  return (
    <section
      role="alert"
      className="flex flex-col items-center gap-3 rounded-(--certping-radius-md) border border-danger-border bg-card px-6 py-10 text-center"
    >
      <WarningCircleIcon className="h-6 w-6 status-danger-text" aria-hidden />
      <div className="space-y-1">
        <p className="text-sm font-semibold text-foreground">{title}</p>
        <p className="text-sm text-muted-foreground">{message}</p>
      </div>
      <Button variant="outline" size="sm" onClick={onRetry} disabled={retrying}>
        <ArrowsClockwiseIcon
          className={retrying ? "animate-spin" : undefined}
        />
        Try again
      </Button>
    </section>
  );
}

export function AuditTrailLoadingState({ label }: { label: string }) {
  return (
    <div
      aria-busy="true"
      aria-label={label}
      className="overflow-hidden rounded-(--certping-radius-md) bg-card"
    >
      <Skeleton className="h-9 rounded-none" />
      {Array.from({ length: 6 }, (_, index) => (
        <div
          key={index}
          className="flex items-center gap-6 border-t border-border px-4 py-3"
        >
          <Skeleton className="h-4 w-36" />
          <div className="w-40 space-y-2">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-3 w-16" />
          </div>
          <Skeleton className="h-4 w-28" />
          <Skeleton className="hidden h-4 w-36 md:block" />
          <Skeleton className="hidden h-5 w-20 md:block" />
          <Skeleton className="hidden h-4 w-56 lg:block" />
        </div>
      ))}
    </div>
  );
}
