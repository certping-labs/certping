// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useMemo, useState } from "react";
import { CaretRightIcon } from "@phosphor-icons/react";

import {
  DetailEmptyState,
  DynamicValue,
} from "@/components/machine-identity/detail-panel";
import { Badge } from "@/components/ui/badge";
import { MorphText } from "@/components/ui/morph-text";
import { Skeleton } from "@/components/ui/skeleton";
import { humanizeConstant, pluralize } from "@/lib/machine-identity/display";
import { cn, formatDateTimeCompact } from "@/lib/utils";
import type { BadgeProps } from "@/components/ui/badge";
import type { DeviceEventDto } from "@/types/machine-identity-backend";

/**
 * `eventStatus` is a free-text field rather than a closed enum, so only values
 * that clearly read as an outcome are coloured; anything unrecognized stays
 * neutral instead of being guessed at.
 */
function eventStatusVariant(status: string | null): BadgeProps["variant"] {
  if (/FAIL|ERROR|REJECT|DENIED|UNMATCHED/i.test(status ?? "")) {
    return "destructive";
  }
  if (
    /SUCCE|COMPLET|ISSUED|VALIDATED|MATCHED|APPLIED|HEALTHY|^OK$/i.test(
      status ?? "",
    )
  ) {
    return "success";
  }
  if (
    /PENDING|START|REQUEST|RUNNING|SIGNING|VALIDATING|RECEIVED/i.test(
      status ?? "",
    )
  ) {
    return "info";
  }
  return "secondary";
}

const RAIL_DOT_CLASSES: Record<string, string> = {
  success: "bg-success",
  destructive: "bg-destructive",
  info: "bg-primary",
  secondary: "bg-muted-foreground/50",
};

function hasDetail(event: DeviceEventDto): boolean {
  return Boolean(event.detail && Object.keys(event.detail).length > 0);
}

interface EventGroup {
  key: string;
  /** Consecutive occurrences of the same event, newest first. */
  events: DeviceEventDto[];
}

/**
 * Folds runs of the same event into one entry.
 *
 * <p>A source that reports health every five minutes produces hundreds of
 * identical "Health reported / Healthy" rows, and the one sync failure in the
 * middle of them is invisible. Only *consecutive* identical events collapse,
 * so the chronology is never reordered and nothing is hidden - the run is
 * still expandable to individual timestamps.
 */
function groupConsecutiveEvents(events: DeviceEventDto[]): EventGroup[] {
  const groups: EventGroup[] = [];
  for (const event of events) {
    const previous = groups.at(-1);
    const first = previous?.events[0];
    const isRepeat =
      first !== undefined &&
      first.eventType === event.eventType &&
      first.eventStatus === event.eventStatus &&
      first.eventMessage === event.eventMessage &&
      !hasDetail(first) &&
      !hasDetail(event);

    if (isRepeat && previous) {
      previous.events.push(event);
    } else {
      groups.push({ key: event.eventXref, events: [event] });
    }
  }
  return groups;
}

interface DeviceEventListProps {
  events: DeviceEventDto[] | undefined;
  isLoading: boolean;
  emptyMessage: string;
}

/**
 * Device activity feed for the IoT backend.
 *
 * <p>Rendered as a timeline: a lifecycle is a sequence, and a flat list of
 * rows all stamped within the same minute gave no sense of order. Each event's
 * `detail` payload and correlation id stay one disclosure away - that is the
 * context needed to trace a failed enrollment back through the agent's logs.
 */
export function DeviceEventList({
  events,
  isLoading,
  emptyMessage,
}: DeviceEventListProps) {
  const groups = useMemo(() => groupConsecutiveEvents(events ?? []), [events]);

  if (isLoading) {
    return (
      <div className="space-y-2 p-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    );
  }

  if (groups.length === 0) {
    return <DetailEmptyState message={emptyMessage} centered />;
  }

  return (
    <ol className="px-4 py-3">
      {groups.map((group, index) => (
        <EventGroupRow
          key={group.key}
          group={group}
          isLast={index === groups.length - 1}
        />
      ))}
    </ol>
  );
}

function EventGroupRow({
  group,
  isLast,
}: {
  group: EventGroup;
  isLast: boolean;
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const event = group.events[0];
  const repeatCount = group.events.length;
  const oldest = group.events[repeatCount - 1];
  const variant = eventStatusVariant(event.eventStatus);
  const expandable = hasDetail(event) || repeatCount > 1;

  return (
    <li className="relative flex gap-3 pb-4 last:pb-0">
      {/*
        The rail is drawn per event, from under this dot to the next one,
        rather than as one absolutely-positioned line down the list: a single
        line has to guess where the first and last dots sit, and guesses wrong
        as soon as a row wraps to two lines.
      */}
      {isLast ? null : (
        <span
          aria-hidden="true"
          className="absolute top-4 bottom-0 left-1.25 w-px bg-border"
        />
      )}
      <span
        aria-hidden="true"
        className={cn(
          "relative z-10 mt-1.5 size-2.5 shrink-0 rounded-full",
          RAIL_DOT_CLASSES[variant ?? "secondary"],
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <span className="text-sm font-medium">
            {humanizeConstant(event.eventType, "Unknown event")}
          </span>
          <Badge variant={variant}>
            {humanizeConstant(event.eventStatus, "Recorded")}
          </Badge>
          {repeatCount > 1 ? (
            <Badge variant="secondary">×{repeatCount}</Badge>
          ) : null}
          <span className="text-xs text-muted-foreground">
            {humanizeConstant(event.actorSource, "System")}
          </span>
          {/*
            A collapsed run prints two full timestamps. As one `nowrap` string
            that is ~250px, which overflows the rail-indented column on a
            phone; split into two atomic dates it breaks at the dash instead.
          */}
          <span className="ml-auto text-xs text-muted-foreground tabular-nums">
            {repeatCount > 1 ? (
              <>
                <span className="whitespace-nowrap">
                  {formatDateTimeCompact(oldest.occurredAt)}
                </span>
                {" – "}
                <span className="whitespace-nowrap">
                  {formatDateTimeCompact(event.occurredAt)}
                </span>
              </>
            ) : (
              <span className="whitespace-nowrap">
                {formatDateTimeCompact(event.occurredAt)}
              </span>
            )}
          </span>
        </div>

        {event.eventMessage ? (
          <p className="mt-0.5 text-sm text-muted-foreground">
            {event.eventMessage}
          </p>
        ) : null}

        {expandable ? (
          <button
            type="button"
            onClick={() => setIsExpanded((open) => !open)}
            aria-expanded={isExpanded}
            className="mt-1 inline-flex items-center gap-1 rounded-sm text-xs font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:outline-hidden"
          >
            <CaretRightIcon
              className={cn(
                "size-3.5 transition-transform",
                isExpanded && "rotate-90",
              )}
              aria-hidden="true"
            />
            <MorphText>
              {repeatCount > 1
                ? isExpanded
                  ? "Hide occurrences"
                  : `Show ${pluralize(repeatCount, "occurrence")}`
                : isExpanded
                  ? "Hide details"
                  : "Show details"}
            </MorphText>
          </button>
        ) : null}

        {isExpanded ? (
          <div className="mt-2 rounded-md border border-border surface-muted px-3 py-2">
            {repeatCount > 1 ? (
              <ul className="space-y-1 text-xs text-muted-foreground tabular-nums">
                {group.events.map((occurrence) => (
                  <li key={occurrence.eventXref}>
                    {formatDateTimeCompact(occurrence.occurredAt)}
                  </li>
                ))}
              </ul>
            ) : (
              <>
                <DynamicValue value={event.detail} />
                {event.correlationId ? (
                  <p className="mt-2 border-t border-border pt-2 font-mono text-xs text-muted-foreground">
                    Correlation {event.correlationId}
                  </p>
                ) : null}
              </>
            )}
          </div>
        ) : null}
      </div>
    </li>
  );
}
