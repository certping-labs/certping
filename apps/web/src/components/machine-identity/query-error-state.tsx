// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React from "react";
import { isAxiosError } from "axios";
import {
  WarningIcon,
  ArrowsClockwiseIcon,
  MagnifyingGlassMinusIcon,
  ShieldWarningIcon,
  WifiSlashIcon,
} from "@phosphor-icons/react";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { FeatureDisabledPage } from "@/components/common/feature-disabled";
import { cn } from "@/lib/utils";
import type { MachineIdentityBackendError } from "@/types/machine-identity-backend";

type FailureKind =
  | "feature-disabled"
  | "forbidden"
  | "not-found"
  | "offline"
  | "transient"
  | "unknown";

interface Classification {
  kind: FailureKind;
  status?: number;
  featureKey?: string;
  /** Server-supplied detail, only used where it is safe and useful to show. */
  serverMessage?: string;
}

/**
 * Maps a failed query onto the one thing the operator can actually do about
 * it. Every branch here is a distinct action - enable a flag, ask for a
 * permission, go back to the list, retry - which is why they cannot collapse
 * into a single "something went wrong".
 */
export function classifyMachineIdentityError(error: unknown): Classification {
  // Callers render this when a surface has nothing to show. No error object at
  // all means the request succeeded and the record simply is not there - the
  // one case where "this no longer exists" is the honest answer.
  if (error === null || error === undefined) {
    return { kind: "not-found" };
  }
  if (!isAxiosError<MachineIdentityBackendError>(error)) {
    return { kind: "unknown" };
  }

  const status = error.response?.status;
  const body = error.response?.data;

  // No response at all: the request never reached the API (offline, DNS,
  // CORS, timeout). Retrying is the only sensible move, and "not found" would
  // be a lie.
  if (!error.response) {
    return { kind: "offline" };
  }
  if (status === 423 || body?.status === 423) {
    return {
      kind: "feature-disabled",
      status: 423,
      featureKey: body?.feature,
    };
  }
  if (status === 401 || status === 403) {
    return { kind: "forbidden", status, serverMessage: body?.message };
  }
  if (status === 404) {
    return { kind: "not-found", status };
  }
  if (status === 429 || (status !== undefined && status >= 500)) {
    return { kind: "transient", status };
  }
  return { kind: "unknown", status, serverMessage: body?.message };
}

interface QueryErrorStateProps {
  error: unknown;
  /** Headline for the generic/transient case, e.g. "Unable to load devices". */
  title: string;
  /** Body for the generic/transient case. */
  description: string;
  /** Noun for the not-found case, e.g. "device". */
  resourceLabel?: string;
  /** Where "Back to list" should go when the resource is missing. */
  backHref?: string;
  backLabel?: string;
  /** Wired to the query's `refetch`; the retry button is hidden without it. */
  onRetry?: () => void;
  isRetrying?: boolean;
  className?: string;
}

/**
 * The module's single failure surface. Detail pages used to report every
 * failure - a 500, an expired session, a disabled feature flag - as "this
 * could not be found", which sent operators hunting for a deleted record that
 * was never deleted.
 */
export function MachineIdentityQueryErrorState({
  error,
  title,
  description,
  resourceLabel = "record",
  backHref,
  backLabel,
  onRetry,
  isRetrying = false,
  className,
}: QueryErrorStateProps) {
  const { kind, status, featureKey, serverMessage } =
    classifyMachineIdentityError(error);

  switch (kind) {
    case "feature-disabled":
      // Same surface as the route gate: the feature was switched off while
      // this page was open.
      return (
        <FeatureDisabledPage
          className={className}
          featureKey={featureKey}
          variant="inline"
        />
      );

    case "forbidden":
      return (
        <ErrorPanel
          className={className}
          icon={ShieldWarningIcon}
          tone="warning"
          title={
            status === 401
              ? "Your session has expired"
              : "You do not have access"
          }
          description={
            status === 401
              ? "Sign in again to continue."
              : (serverMessage ??
                "Your role does not include permission to view this. Ask an organization administrator for access.")
          }
        />
      );

    case "not-found":
      return (
        <ErrorPanel
          className={className}
          icon={MagnifyingGlassMinusIcon}
          tone="neutral"
          title={`This ${resourceLabel} no longer exists`}
          description={`It may have been removed, or it belongs to a different organization. Nothing was deleted by opening this page.`}
          action={
            backHref ? (
              <Button asChild size="sm" variant="outline">
                <Link href={backHref}>{backLabel ?? "Back to list"}</Link>
              </Button>
            ) : undefined
          }
        />
      );

    case "offline":
      return (
        <ErrorPanel
          className={className}
          icon={WifiSlashIcon}
          tone="warning"
          title="CertPing could not be reached"
          description="The request did not reach the API. Check your connection, then try again."
          action={<RetryButton onRetry={onRetry} isRetrying={isRetrying} />}
        />
      );

    default:
      return (
        <ErrorPanel
          className={className}
          icon={WarningIcon}
          tone="danger"
          title={title}
          // A 5xx is transient and a retry is genuinely worth a try; anything
          // else gets the caller's own wording rather than false reassurance.
          description={
            kind === "transient"
              ? `${description} This usually clears on its own.`
              : description
          }
          footnote={status ? `HTTP ${status}` : undefined}
          action={<RetryButton onRetry={onRetry} isRetrying={isRetrying} />}
        />
      );
  }
}

function RetryButton({
  onRetry,
  isRetrying,
}: {
  onRetry?: () => void;
  isRetrying?: boolean;
}) {
  if (!onRetry) return null;
  return (
    <Button size="sm" variant="outline" onClick={onRetry} disabled={isRetrying}>
      <ArrowsClockwiseIcon
        className={cn("size-4", isRetrying && "animate-spin")}
        aria-hidden="true"
      />
      {isRetrying ? "Retrying" : "Try again"}
    </Button>
  );
}

const PANEL_TONE_CLASSES = {
  neutral: "text-muted-foreground",
  warning: "status-warning-text",
  danger: "status-danger-text",
} as const;

function ErrorPanel({
  icon: Icon,
  tone,
  title,
  description,
  action,
  footnote,
  className,
}: {
  icon: PhosphorIcon;
  tone: keyof typeof PANEL_TONE_CLASSES;
  title: string;
  description: string;
  action?: React.ReactNode;
  footnote?: string;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center gap-3 rounded-lg border border-dashed border-border bg-card px-6 py-10 text-center",
        className,
      )}
    >
      <Icon
        className={cn("size-6", PANEL_TONE_CLASSES[tone])}
        aria-hidden="true"
      />
      <div className="space-y-1">
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        <p className="mx-auto max-w-md text-sm text-muted-foreground">
          {description}
        </p>
      </div>
      {action}
      {footnote ? (
        <p className="font-mono text-xs text-muted-foreground/70">{footnote}</p>
      ) : null}
    </div>
  );
}
