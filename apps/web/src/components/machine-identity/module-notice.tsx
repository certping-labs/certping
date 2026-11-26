// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import {
  WarningIcon,
  InfoIcon,
  WarningOctagonIcon,
} from "@phosphor-icons/react/dist/ssr";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import { cn } from "@/lib/utils";

const NOTICE_TONES = {
  info: {
    icon: InfoIcon,
    className:
      "border-[hsl(var(--status-info-border))] bg-[hsl(var(--status-info-bg))] status-info-text",
  },
  warning: {
    icon: WarningIcon,
    className:
      "border-[hsl(var(--status-warning-border))] bg-[hsl(var(--status-warning-bg))] status-warning-text",
  },
  danger: {
    icon: WarningOctagonIcon,
    className:
      "border-[hsl(var(--status-danger-border))] bg-[hsl(var(--status-danger-bg))] status-danger-text",
  },
} as const satisfies Record<string, { icon: PhosphorIcon; className: string }>;

interface ModuleNoticeProps {
  tone: keyof typeof NOTICE_TONES;
  children: React.ReactNode;
  /** Right-aligned slot for the one action that resolves the notice. */
  action?: React.ReactNode;
  className?: string;
}

/**
 * Explains a state the surrounding controls cannot express on their own.
 *
 * <p>Machine Identity has several: a provider-owned profile that silently
 * loses its Edit button, a push that failed after a successful-looking save, a
 * source whose sync stopped. Each of those used to be invisible, leaving the
 * operator to infer it from an absence.
 */
export function ModuleNotice({
  tone,
  children,
  action,
  className,
}: ModuleNoticeProps) {
  const { icon: Icon, className: toneClassName } = NOTICE_TONES[tone];

  return (
    <div
      className={cn(
        "flex flex-wrap items-start gap-3 rounded-lg border px-4 py-3 text-sm",
        toneClassName,
        className,
      )}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <p className="min-w-0 flex-1">{children}</p>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}
