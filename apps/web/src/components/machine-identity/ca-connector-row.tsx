// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Link from "next/link";
import React from "react";

import { CaConnectorLabel } from "@/components/machine-identity/ca-connector-label";
import { MetricPair } from "@/components/machine-identity/metric-pair";
import { ModuleNotice } from "@/components/machine-identity/module-notice";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { caConnectorStatusVariant } from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";
import type { CaConnectorResponse } from "@/types/machine-identity-backend";

interface CaConnectorRowProps {
  connector: CaConnectorResponse;
}

/**
 * `issues` is arbitrary provider JSON, so the row only claims a count when the
 * CA actually sent a list. Anything else is left to the detail page rather
 * than guessed at here.
 */
function issueCount(issues: unknown): number {
  return Array.isArray(issues) ? issues.length : 0;
}

/** One row in the CA connectors list: identity, status, and latest check. */
export function CaConnectorRow({ connector }: CaConnectorRowProps) {
  const href = `/integrations/certificate-authorities/${connector.connectorId}`;
  const issues = issueCount(connector.issues);

  return (
    <article className="space-y-3 rounded-lg border border-border bg-card p-4">
      {/* Same tablet collision as `DeviceSourceRow`; see the note there. */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,18rem)_minmax(0,1fr)_auto] xl:items-center">
        <div className="min-w-0">
          <Link href={href} className="block hover:text-primary">
            <CaConnectorLabel
              caProvider={connector.caProvider}
              className="font-medium"
            />
          </Link>
          <p className="truncate text-xs text-muted-foreground">
            {connector.connectorId}
          </p>
        </div>

        <dl className="grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
          <MetricPair
            label="Status"
            node={
              <Badge variant={caConnectorStatusVariant(connector.status)}>
                {humanizeConstant(connector.status)}
              </Badge>
            }
          />
          <MetricPair
            label="Latency"
            value={
              connector.latencyMs != null ? `${connector.latencyMs} ms` : "—"
            }
          />
          <MetricPair
            label="Last checked"
            value={formatDateTimeCompact(connector.checkedAt)}
          />
        </dl>

        <div className="flex flex-wrap items-center gap-2 xl:justify-end">
          <Badge variant={connector.enabled ? "success" : "secondary"}>
            {connector.enabled ? "Enabled" : "Disabled"}
          </Badge>
        </div>
      </div>

      {connector.stale ? (
        <ModuleNotice tone="warning">
          No health report since {formatDateTimeCompact(connector.receivedAt)}:
          the agent that reports this connector may be stopped or removed.
        </ModuleNotice>
      ) : null}

      {issues > 0 ? (
        <ModuleNotice
          tone={connector.status === "HEALTHY" ? "warning" : "danger"}
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={href}>Review</Link>
            </Button>
          }
        >
          {issues === 1
            ? "The CA reported 1 issue in its last health check."
            : `The CA reported ${issues} issues in its last health check.`}
        </ModuleNotice>
      ) : null}
    </article>
  );
}
