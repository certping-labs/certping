// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Link from "next/link";
import React from "react";
import {
  CircleNotchIcon,
  PauseCircleIcon,
  ArrowsClockwiseIcon,
} from "@phosphor-icons/react/dist/ssr";

import { MetricPair } from "@/components/machine-identity/metric-pair";
import { ModuleNotice } from "@/components/machine-identity/module-notice";
import { ProviderLabel } from "@/components/machine-identity/provider-label";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  sourceHealthVariant,
  sourceSyncStatusVariant,
} from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { cn, formatDateTimeCompact } from "@/lib/utils";
import type {
  DeviceSourceDto,
  DeviceSourceHealthStatus,
} from "@/types/machine-identity-backend";

/** A health message is only alarming if the health status says it is. */
function healthNoticeTone(
  status: DeviceSourceHealthStatus,
): "info" | "warning" | "danger" {
  if (status === "UNHEALTHY") return "danger";
  if (status === "DEGRADED" || status === "STALE") return "warning";
  return "info";
}

/** Human progress for a run that is still streaming device pages in. */
function syncProgress(sync: DeviceSourceDto["sync"]): string | null {
  if (!sync) return null;
  if (sync.status !== "PENDING" && sync.status !== "RUNNING") return null;
  const processed = sync.processedDeviceCount ?? 0;
  if (sync.expectedDeviceCount != null) {
    return `${processed.toLocaleString()} of ${sync.expectedDeviceCount.toLocaleString()} devices`;
  }
  return processed > 0
    ? `${processed.toLocaleString()} devices so far`
    : "Waiting for the agent";
}

interface DeviceSourceRowProps {
  source: DeviceSourceDto;
  isSyncing: boolean;
  onSync: () => void;
  onStopSync: () => void;
  isStoppingSync: boolean;
  /** `iot_source:manage`; without it the sync controls are not rendered. */
  canManageSync: boolean;
}

/** One row in the device sources list: identity, health, sync state, and controls. */
export function DeviceSourceRow({
  source,
  isSyncing,
  onSync,
  onStopSync,
  isStoppingSync,
  canManageSync,
}: DeviceSourceRowProps) {
  const href = `/integrations/device-sources/${source.sourceXref}`;
  const progress = syncProgress(source.sync);
  const permissions = source.health?.permissions ?? [];
  const grantedPermissions = permissions.filter(
    (permission) => permission.granted,
  ).length;
  const missingPermissions = permissions.length - grantedPermissions;

  return (
    <article className="space-y-3 rounded-lg border border-border bg-card p-4">
      {/*
        Side-by-side only at `xl`. At tablet width the three tracks (name,
        four metrics, two buttons) each got about a third of ~700px, which
        truncated "Last advertised" to "Sep 1, ..." and pushed the buttons into
        the metrics beside them. Stacked, each band gets the full row.
      */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,18rem)_minmax(0,1fr)_auto] xl:items-center">
        <div className="min-w-0">
          <Link href={href} className="font-medium hover:text-primary">
            {source.displayName}
          </Link>
          <ProviderLabel
            provider={source.provider}
            className="block text-xs text-muted-foreground"
          />
        </div>

        {/* Wide only from `md`: at 640px four cells are ~136px each and five
            are ~110px, both narrower than a formatted timestamp, so every
            "Last advertised" in the list truncated. */}
        <dl
          className={cn(
            "grid grid-cols-2 gap-3 text-sm",
            source.provider === "INTUNE" ? "md:grid-cols-5" : "md:grid-cols-4",
          )}
        >
          <MetricPair
            label="Devices"
            value={source.deviceCount.toLocaleString()}
          />
          <MetricPair
            label="Health"
            node={
              <Badge
                variant={
                  source.health
                    ? sourceHealthVariant(source.health.status)
                    : "secondary"
                }
              >
                {source.health
                  ? humanizeConstant(source.health.status)
                  : "Not reported"}
              </Badge>
            }
          />
          <MetricPair
            label="Sync"
            node={
              source.sync ? (
                <span className="flex flex-col items-start gap-0.5">
                  <Badge variant={sourceSyncStatusVariant(source.sync.status)}>
                    {humanizeConstant(source.sync.status)}
                  </Badge>
                  {progress ? (
                    <span className="text-xs text-muted-foreground">
                      {progress}
                    </span>
                  ) : null}
                </span>
              ) : (
                <span className="text-muted-foreground">Never run</span>
              )
            }
          />
          <MetricPair
            label="Last advertised"
            value={formatDateTimeCompact(source.lastAdvertisedAt)}
          />
          {source.provider === "INTUNE" ? (
            <MetricPair
              label="Permissions"
              node={
                permissions.length > 0 ? (
                  <Badge
                    variant={missingPermissions === 0 ? "success" : "warning"}
                  >
                    {grantedPermissions} of {permissions.length}
                  </Badge>
                ) : (
                  <span className="text-muted-foreground">Not reported</span>
                )
              }
            />
          ) : null}
        </dl>

        <div className="flex flex-wrap items-center gap-2 xl:justify-end">
          {canManageSync && source.syncEnabled ? (
            <Button
              variant="outline"
              size="sm"
              onClick={onStopSync}
              disabled={isStoppingSync}
            >
              <PauseCircleIcon className="size-4" aria-hidden="true" />
              Stop schedule
            </Button>
          ) : null}
          {canManageSync ? (
            <Button size="sm" onClick={onSync} disabled={isSyncing}>
              {isSyncing ? (
                <CircleNotchIcon
                  className="size-4 animate-spin"
                  aria-hidden="true"
                />
              ) : (
                <ArrowsClockwiseIcon className="size-4" aria-hidden="true" />
              )}
              {isSyncing ? "Syncing" : "Sync now"}
            </Button>
          ) : null}
        </div>
      </div>

      {!source.syncEnabled ? (
        <ModuleNotice tone="warning">
          Scheduled syncs are off for this source, so its inventory only
          refreshes when someone runs one. Sync now re-enables the hourly
          schedule.
        </ModuleNotice>
      ) : null}

      {source.health?.statusMessage ? (
        <ModuleNotice tone={healthNoticeTone(source.health.status)}>
          {source.health.statusMessage}
        </ModuleNotice>
      ) : null}

      {source.sync?.lastError ? (
        <ModuleNotice tone="danger">
          Last sync reported: {source.sync.lastError}
        </ModuleNotice>
      ) : null}
    </article>
  );
}
