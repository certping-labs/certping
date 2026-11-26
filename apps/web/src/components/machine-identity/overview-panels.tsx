// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { CaConnectorLabel } from "@/components/machine-identity/ca-connector-label";
import {
  DetailEmptyState,
  DetailPanel,
} from "@/components/machine-identity/detail-panel";
import { ProviderLabel } from "@/components/machine-identity/provider-label";
import { Badge } from "@/components/ui/badge";
import { caConnectorStatusVariant } from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";
import type {
  CaConnectorResponse,
  IotSourceDeviceCount,
  IotSourceOverview,
} from "@/types/machine-identity-backend";

/**
 * Source-breakdown and issuer-health panels for the main dashboard's Machine
 * Identity section. The device inventory's posture panels share the panel
 * chrome, so the two surfaces never drift apart.
 */

/**
 * Alias for {@link DetailPanel}.
 *
 * <p>These panels used to carry their own header style - uppercase, muted,
 * smaller - so the dashboard's "OPERATING SYSTEMS" and a detail page's
 * "Identity" looked like two different products. One panel chrome, one place
 * to change it.
 */
export function OverviewPanel({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return <DetailPanel title={title}>{children}</DetailPanel>;
}

export function SourceBreakdownList({
  bySource,
  sourceHealth,
}: {
  bySource: IotSourceDeviceCount[];
  sourceHealth: IotSourceOverview;
}) {
  return (
    <div>
      <div className="grid grid-cols-3 gap-3 border-b border-border px-4 py-2.5 text-center text-xs">
        <HealthStat
          label="Healthy"
          value={sourceHealth.healthy}
          tone="success"
        />
        <HealthStat
          label="Degraded"
          value={sourceHealth.degraded + sourceHealth.stale}
          tone="warning"
        />
        <HealthStat
          label="Unhealthy"
          value={sourceHealth.unhealthy}
          tone="destructive"
        />
      </div>
      {bySource.length === 0 ? (
        <DetailEmptyState message="No device source has advertised itself yet. Sources appear here automatically once an agent reports its first health check." />
      ) : (
        <ul className="divide-y divide-border">
          {bySource.map((entry) => (
            <li
              key={entry.sourceXref}
              className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-4 py-2.5"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">
                  {entry.displayName}
                </p>
                <ProviderLabel
                  provider={entry.provider}
                  className="text-xs text-muted-foreground"
                />
              </div>
              <span className="text-sm whitespace-nowrap text-muted-foreground">
                {entry.deviceCount.toLocaleString()}{" "}
                {entry.deviceCount === 1 ? "device" : "devices"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const HEALTH_STAT_TONE_CLASSES = {
  success: "text-success",
  warning: "text-warning",
  destructive: "text-destructive",
} as const;

function HealthStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: keyof typeof HEALTH_STAT_TONE_CLASSES;
}) {
  return (
    <div>
      <p
        className={`text-base font-semibold ${HEALTH_STAT_TONE_CLASSES[tone]}`}
      >
        {value}
      </p>
      <p className="text-muted-foreground">{label}</p>
    </div>
  );
}

export function CaConnectorList({
  connectors,
}: {
  connectors: CaConnectorResponse[];
}) {
  if (connectors.length === 0) {
    return (
      <DetailEmptyState message="No certificate authority has reported in yet. Connectors appear here once an agent sends its first CA health report." />
    );
  }

  return (
    <ul className="divide-y divide-border">
      {connectors.map((connector) => (
        <li
          key={connector.connectorId}
          className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-4 py-2.5"
        >
          <div className="min-w-0">
            <CaConnectorLabel
              caProvider={connector.caProvider}
              className="font-medium"
            />
            <p className="truncate text-xs text-muted-foreground">
              {connector.connectorId} · checked{" "}
              {formatDateTimeCompact(connector.checkedAt)}
            </p>
          </div>
          <Badge variant={caConnectorStatusVariant(connector.status)}>
            {humanizeConstant(connector.status)}
          </Badge>
        </li>
      ))}
    </ul>
  );
}
