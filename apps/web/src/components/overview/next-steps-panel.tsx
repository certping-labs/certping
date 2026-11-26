// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  WarningOctagonIcon,
  WarningIcon,
  CheckCircleIcon,
  CloudSlashIcon,
  SparkleIcon,
} from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  describeFailedSources,
  type NextStep,
  type NextStepTone,
} from "@/lib/overview-next-steps";
import { cn } from "@/lib/utils";

const TONE_ICON: Record<
  NextStepTone,
  { icon: React.ComponentType<{ className?: string }>; className: string }
> = {
  critical: {
    icon: WarningOctagonIcon,
    className: "bg-danger-soft text-danger-foreground",
  },
  warning: {
    icon: WarningIcon,
    className: "bg-warning-soft text-warning-foreground",
  },
  opportunity: {
    icon: SparkleIcon,
    className: "bg-primary-soft text-primary-soft-foreground",
  },
};

export const SNOOZE_STORAGE_KEY = "certping:overview:snoozed-steps";
const SNOOZE_MS = 30 * 86_400_000;

type Snoozes = Record<string, number>;

export function readSnoozes(now: number = Date.now()): Snoozes {
  try {
    const raw = window.localStorage.getItem(SNOOZE_STORAGE_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    if (!parsed || typeof parsed !== "object") return {};
    const active: Snoozes = {};
    for (const [id, until] of Object.entries(parsed)) {
      if (typeof until === "number" && until > now) active[id] = until;
    }
    return active;
  } catch {
    return {};
  }
}

function writeSnoozes(snoozes: Snoozes) {
  try {
    window.localStorage.setItem(SNOOZE_STORAGE_KEY, JSON.stringify(snoozes));
  } catch {
    return;
  }
}

function useSnoozes() {
  const [snoozes, setSnoozes] = useState<Snoozes>({});
  useEffect(() => setSnoozes(readSnoozes()), []);
  const snooze = useCallback((id: string) => {
    const next = { ...readSnoozes(), [id]: Date.now() + SNOOZE_MS };
    writeSnoozes(next);
    setSnoozes(next);
  }, []);
  return { snoozes, snooze };
}

export function NextStepsPanel({
  steps,
  isLoading,
  primaryFirst = true,
  failedSources = [],
  onRetry,
}: {
  steps: readonly NextStep[];
  isLoading: boolean;
  primaryFirst?: boolean;
  failedSources?: readonly string[];
  onRetry?: () => void;
}) {
  const { snoozes, snooze } = useSnoozes();
  const visible = useMemo(
    () =>
      steps.filter(
        (step) => step.tone !== "opportunity" || !(step.id in snoozes),
      ),
    [steps, snoozes],
  );
  const incomplete = failedSources.length > 0;

  return (
    <section
      aria-labelledby="next-steps-title"
      className="rounded-xl border border-border bg-card"
    >
      <div className="flex flex-wrap items-end justify-between gap-3 px-5 pt-4 pb-3">
        <h2
          id="next-steps-title"
          className="text-[15px] font-semibold tracking-[-0.015em] text-foreground"
        >
          Next steps
        </h2>
      </div>

      {isLoading ? (
        <ul className="space-y-1 px-2 pb-2">
          {Array.from({ length: 3 }).map((_, index) => (
            <li key={index} className="flex items-center gap-3 px-3 py-3">
              <Skeleton className="size-9 rounded-[10px]" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-3.5 w-56 rounded-full" />
                <Skeleton className="h-3 w-72 rounded-full" />
              </div>
              <Skeleton className="h-8 w-24 rounded-full" />
            </li>
          ))}
        </ul>
      ) : null}

      {!isLoading && incomplete ? (
        <div
          role="status"
          className="mx-5 mb-3 flex flex-wrap items-center gap-3 rounded-[10px] border border-border px-3 py-2.5 text-sm"
        >
          <CloudSlashIcon
            className="size-4 shrink-0 text-muted-foreground"
            aria-hidden
          />
          <p className="min-w-0 flex-1 text-muted-foreground">
            We couldn&apos;t check {describeFailedSources(failedSources)} just
            now, so this list may be incomplete. Try again in a moment.
          </p>
          {onRetry ? (
            <Button size="sm" variant="ghost" onClick={onRetry}>
              Try again
            </Button>
          ) : null}
        </div>
      ) : null}

      {isLoading ? null : visible.length === 0 && !incomplete ? (
        <div className="flex items-center gap-3 px-5 pb-5">
          <span className="grid size-9 place-items-center rounded-[10px] bg-success-soft text-success-foreground">
            <CheckCircleIcon className="size-4" aria-hidden />
          </span>
          <div>
            <p className="text-sm font-medium text-foreground">All set</p>
            <p className="text-sm text-muted-foreground">
              Nothing needs you right now. Your certificates are covered.
            </p>
          </div>
        </div>
      ) : visible.length > 0 ? (
        <ol className="px-2 pb-2">
          {visible.map((step, index) => (
            <NextStepRow
              key={step.id}
              step={step}
              isPrimary={primaryFirst && index === 0}
              onSnooze={step.tone === "opportunity" ? snooze : undefined}
            />
          ))}
        </ol>
      ) : null}
    </section>
  );
}

function NextStepRow({
  step,
  isPrimary,
  onSnooze,
}: {
  step: NextStep;
  isPrimary: boolean;
  onSnooze?: (id: string) => void;
}) {
  const { icon: Icon, className } = TONE_ICON[step.tone];
  const variant = isPrimary ? "default" : "outline";
  const { action } = step;

  return (
    <li
      data-tone={step.tone}
      className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-3 gap-y-2 rounded-[10px] px-3 py-3 transition-colors hover:surface-muted sm:grid-cols-[auto_minmax(0,1fr)_auto]"
    >
      <span
        className={cn(
          "grid size-9 place-items-center rounded-[10px]",
          className,
        )}
      >
        <Icon className="size-4" aria-hidden />
      </span>
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-foreground">
          {step.title}
        </p>
        <p className="text-sm text-muted-foreground">{step.detail}</p>
      </div>
      <div className="col-span-2 flex flex-wrap items-center gap-1 pl-12 sm:col-span-1 sm:justify-end sm:pl-0">
        {onSnooze ? (
          <Button
            size="sm"
            variant="ghost"
            aria-label={`Hide for 30 days: ${step.title}`}
            onClick={() => onSnooze(step.id)}
          >
            Hide for 30 days
          </Button>
        ) : null}
        {!action ? (
          step.note ? (
            <span className="px-2 text-sm text-muted-foreground">
              {step.note}
            </span>
          ) : null
        ) : (
          <Button asChild size="sm" variant={variant}>
            <Link href={action.href}>{action.label}</Link>
          </Button>
        )}
      </div>
    </li>
  );
}
