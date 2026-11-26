// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { useSearchParams } from "next/navigation";

import { AuditTrailAccessPanel } from "@/components/audit-trail/audit-trail-access-panel";
import { AuditTrailPanel } from "@/components/audit-trail/audit-trail-panel";
import { useAuditTrailAccessActivities } from "@/hooks/audit-trail";
import { useAuth } from "@/hooks/use-auth";
import type { AuditTrailSource } from "@/lib/audit-trail-source";

/** The query parameter that names the open view, e.g. `?view=access`. */
export const AUDIT_TRAIL_VIEW_PARAM = "view";

interface AuditTrailProps {
  /** The service whose trail this shows; keep it stable across renders. */
  source: AuditTrailSource;
  /** The super admin's view of every organization; it has no Access view. */
  platform?: boolean;
}

/**
 * A source's logs behind one switcher: the activity log, and the Access log
 * when the source has one and `?view=` names it. An `optional` Access route
 * is asked for its activities first and offered only once they arrive, so a
 * service that does not serve it yet shows the activity log alone.
 */
export function AuditTrail({ source, platform = false }: AuditTrailProps) {
  const view = useSearchParams().get(AUDIT_TRAIL_VIEW_PARAM);
  const { user, isLoading: isLoadingAuth } = useAuth();
  const access = platform ? undefined : source.access;
  const probe = useAuditTrailAccessActivities(
    // A stand-in keeps the hook unconditional; it is never enabled.
    access ?? NO_ACCESS,
    Boolean(access?.optional && access.canView(user)) && !isLoadingAuth,
  );
  const accessReady =
    access !== undefined &&
    access.canView(user) &&
    (!access.optional || probe.isSuccess);

  // Opened by link: the Access panel says itself when its route is missing.
  if (access && view === access.viewId) {
    return <AuditTrailAccessPanel source={access} showViews={accessReady} />;
  }
  return (
    <AuditTrailPanel
      source={source}
      platform={platform}
      showViews={!source.access || accessReady}
    />
  );
}

const NO_ACCESS = {
  queryKey: ["audit-trail-no-access"],
  activities: async () => [],
} as const;
