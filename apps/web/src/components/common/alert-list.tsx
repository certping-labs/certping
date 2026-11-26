// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Link from "next/link";
import React, { useMemo } from "react";
import { Badge } from "@/components/ui/badge";
import { humanizeEnum } from "@/lib/humanize";
import { cn, formatDate } from "@/lib/utils";
import {
  CircleNotchIcon,
  ShieldWarningIcon,
} from "@phosphor-icons/react/dist/ssr";
import {
  useCanMarkAlertRead,
  useLatestSystemAlerts,
  useMarkSystemAlertAsRead,
  type SystemAlert,
} from "@/hooks/incidents";
import { getAlertKey, getAlertTypeLabel } from "@/lib/alerts";
import { useAuth } from "@/hooks/use-auth";
import { canViewAlerts as userCanViewAlerts } from "@/lib/authz";

const getAlertTarget = (domain: string | null): string => domain || "No domain";

const getAlertMessage = (message: string | null): string =>
  message || "No message available";

/** On one domain's page the domain is already known, so the alert type leads. */
const getRowText = (
  alert: SystemAlert,
  domain: string | undefined,
): { title: string; detail: string } =>
  domain
    ? {
        title: getAlertTypeLabel(alert.alertType),
        detail: getAlertMessage(alert.message),
      }
    : {
        title: getAlertTarget(alert.domain),
        detail: `${getAlertTypeLabel(alert.alertType)}: ${getAlertMessage(alert.message)}`,
      };

const iconTone = (severity: string): string =>
  severity === "INFO" ? "status-info-text" : "status-warning-text";

export interface AlertListProps {
  onlyUnread?: boolean;
  limit?: number;
  markReadOnClick?: boolean;
  /** Only alerts about this domain (the domain detail page). */
  domain?: string;
  /** Hide the empty state; the parent decides what to show instead. */
  hideEmpty?: boolean;
  /** Shown above the rows only, never over a loading or empty state. */
  heading?: string;
}

export function AlertList({
  onlyUnread = false,
  limit = 6,
  markReadOnClick = false,
  domain,
  hideEmpty = false,
  heading,
}: AlertListProps) {
  const { user } = useAuth();
  const canViewAlerts = userCanViewAlerts(user);
  const alertsQuery = useLatestSystemAlerts({ enabled: canViewAlerts });
  const canMarkAlert = useCanMarkAlertRead();
  const markRead = useMarkSystemAlertAsRead();

  const filteredAlerts = useMemo(() => {
    const alerts = alertsQuery.data ?? [];
    // Resolved alerts belong to the history on /incidents. An alert without a status is a
    // write-once message, "problem ended" included, so it always stays.
    return alerts
      .filter((alert) => alert.status !== "RESOLVED")
      .filter((alert) => !onlyUnread || alert.unread)
      .filter((alert) => !domain || alert.domain === domain)
      .slice(0, limit);
  }, [alertsQuery.data, onlyUnread, domain, limit]);

  if (alertsQuery.isLoading) {
    if (hideEmpty) {
      return null;
    }
    return (
      <div className="flex h-full min-h-32 w-full items-center justify-center">
        <CircleNotchIcon className="size-6 animate-spin" />
      </div>
    );
  }

  if (
    hideEmpty &&
    (!canViewAlerts || (alertsQuery.isError && filteredAlerts.length === 0))
  ) {
    return null;
  }

  if (!canViewAlerts) {
    return (
      <div className="flex items-center justify-center p-8 text-sm text-muted-foreground">
        No recent alerts
      </div>
    );
  }

  // Rows from an earlier load stay on screen when a refetch fails.
  if (alertsQuery.isError && filteredAlerts.length === 0) {
    return (
      <div className="flex items-center justify-center p-6 text-sm text-destructive">
        Failed to load alerts
      </div>
    );
  }

  if (filteredAlerts.length === 0) {
    if (hideEmpty) {
      return null;
    }
    return (
      <>
        <div className="flex items-center justify-center p-8 text-sm text-muted-foreground">
          {onlyUnread ? "No unread alerts" : "No recent alerts"}
        </div>
      </>
    );
  }

  // With a heading the list is a page section, and page sections use px-5.
  const edgePadding = heading ? "px-5" : "px-4";

  return (
    <div className="flex w-full min-w-0 flex-col overflow-hidden">
      {heading ? (
        <h2
          className={cn(
            "border-b border-border/70 py-4 text-base font-semibold text-foreground",
            edgePadding,
          )}
        >
          {heading}
        </h2>
      ) : null}
      {filteredAlerts.map((alert) => {
        const { title, detail } = getRowText(alert, domain);
        return (
          <Link
            key={getAlertKey(alert)}
            href={`/incidents?alert=${encodeURIComponent(getAlertKey(alert))}`}
            className={cn(
              "grid w-full min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-3 overflow-hidden py-2.5 text-left text-sm transition-colors hover:bg-accent",
              "border-b last:border-b-0",
              edgePadding,
              alert.unread && "bg-primary/5",
            )}
            onClick={() => {
              if (
                !markReadOnClick ||
                !alert.unread ||
                markRead.isPending ||
                !canMarkAlert(alert.source)
              )
                return;
              markRead.mutate({ id: alert.id, source: alert.source });
            }}
          >
            <div className="flex min-w-0 items-center gap-3 overflow-hidden">
              <div className="shrink-0">
                <ShieldWarningIcon
                  className={cn(iconTone(alert.severity), "h-4 w-4")}
                />
              </div>
              <div className="flex min-w-0 flex-col">
                <div className="line-clamp-1 font-medium">{title}</div>
                <div className="line-clamp-1 text-xs text-muted-foreground">
                  {detail}
                </div>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2 pr-0.5">
              <Badge
                variant={
                  alert.severity === "CRITICAL"
                    ? "destructive"
                    : alert.severity === "WARNING"
                      ? "warning"
                      : alert.severity === "INFO"
                        ? "info"
                        : "secondary"
                }
                className="text-xs"
              >
                {humanizeEnum(alert.severity)}
              </Badge>
              <time
                dateTime={alert.createdAt}
                className="text-xs text-muted-foreground tabular-nums"
              >
                {formatDate(alert.createdAt)}
              </time>
              {/* Always laid out so every date ends on the same edge, read or unread. */}
              <span
                aria-hidden
                className={cn(
                  "h-2 w-2 rounded-full",
                  alert.unread ? "bg-primary" : "invisible",
                )}
              />
            </div>
          </Link>
        );
      })}
    </div>
  );
}
