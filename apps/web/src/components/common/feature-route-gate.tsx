// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { type ReactNode } from "react";
import { usePathname } from "next/navigation";
import { useShallow } from "zustand/react/shallow";
import { ArrowsClockwiseIcon, WarningCircleIcon } from "@phosphor-icons/react";

import { FeatureDisabledPage } from "@/components/common/feature-disabled";
import { FeatureNeedsOrganizationPage } from "@/components/common/feature-needs-organization";
import { FeatureStatePanel } from "@/components/common/feature-state-panel";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useRetryFeatureFlags } from "@/hooks/use-feature-flags";
import {
  type RouteAvailabilityResult,
  resolveRouteAvailability,
} from "@/lib/feature-routes";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";

/**
 * Enforces `FEATURE_ROUTE_RULES` for every page in the (main) area, in one
 * place, inside the workspace pane so the sidebar and toolbar never shift.
 * RBAC runs first in `AuthProvider`; this only answers "is the feature on".
 *
 * - unknown → skeleton: the page never mounts, so it cannot fire requests
 *   the API would refuse, and never flashes "not available" during load.
 * - off → the not-available page for the first blocking flag.
 * - needs an organization the session lacks → says so; the page never
 *   mounts, so none of its organization-scoped requests are sent.
 * - error (the first flag fetch failed) → a retryable error, not the page:
 *   failing open would show features that may be off.
 */
export function FeatureRouteGate({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const isSuperAdmin = useAuthStore((state) => Boolean(state.isSuperAdmin));
  const result = useFeatureFlagStore(
    useShallow((state) =>
      resolveRouteAvailability(pathname, {
        status: state.status,
        effectiveMap: state.effectiveMap,
        isSuperAdmin,
      }),
    ),
  );

  return renderForAvailability(result, children);
}

function renderForAvailability(
  { availability, blockingKey }: RouteAvailabilityResult,
  children: ReactNode,
) {
  switch (availability) {
    case "on":
      return <>{children}</>;
    case "pending":
      return <FeatureRoutePending />;
    case "error":
      return <FeatureFlagsErrorState />;
    case "off":
      return <FeatureDisabledPage featureKey={blockingKey} />;
    case "needs-organization":
      return <FeatureNeedsOrganizationPage featureKey={blockingKey} />;
  }
}

function FeatureRoutePending() {
  return (
    <div
      role="status"
      aria-label="Loading"
      aria-busy="true"
      className="space-y-5 p-4 sm:p-6"
    >
      <Skeleton className="h-8 w-64 max-w-full" />
      <Skeleton className="h-4 w-96 max-w-full" />
      <Skeleton className="h-72 w-full rounded-xl" />
    </div>
  );
}

export function FeatureFlagsErrorState() {
  const { retry, isRetrying } = useRetryFeatureFlags();
  return (
    <FeatureStatePanel
      role="alert"
      iconClassName="status-warning-text"
      icon={<WarningCircleIcon className="size-5" />}
      title={<>This page couldn&apos;t load</>}
      body={
        <>
          CertPing couldn&apos;t check which features are on for your
          organization. Try again in a moment.
        </>
      }
      actions={
        <Button onClick={retry} disabled={isRetrying} variant="outline">
          <ArrowsClockwiseIcon
            aria-hidden="true"
            className={cn(
              isRetrying && "animate-spin motion-reduce:animate-none",
            )}
          />
          {isRetrying ? "Trying again" : "Try again"}
        </Button>
      }
    />
  );
}
