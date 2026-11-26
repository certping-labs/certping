// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { use } from "react";

import { CaConnectorLabel } from "@/components/machine-identity/ca-connector-label";
import {
  DetailPanel,
  DetailRow,
  DynamicDataPanel,
  PanelMasonry,
} from "@/components/machine-identity/detail-panel";
import { ModuleNotice } from "@/components/machine-identity/module-notice";
import { MachineIdentityQueryErrorState } from "@/components/machine-identity/query-error-state";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { useCaConnector } from "@/hooks/machine-identity/use-ca-connectors";
import { caConnectorStatusVariant } from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";

const CONNECTORS_HREF = "/integrations/device-sources";

export default function CaConnectorDetailPage({
  params,
}: {
  params: Promise<{ connectorId: string }>;
}) {
  const { connectorId } = use(params);
  const connectorQuery = useCaConnector(connectorId);

  if (connectorQuery.isLoading) {
    return (
      <div className="space-y-4 p-4 md:p-6">
        <Skeleton className="h-16 w-full max-w-xl" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (connectorQuery.error || !connectorQuery.data) {
    return (
      <div className="p-4 md:p-6">
        <MachineIdentityQueryErrorState
          error={connectorQuery.error}
          title="Unable to load CA connector"
          description="This CA connector could not be loaded."
          resourceLabel="CA connector"
          backHref={CONNECTORS_HREF}
          backLabel="Back to connectors"
          onRetry={() => void connectorQuery.refetch()}
          isRetrying={connectorQuery.isFetching}
        />
      </div>
    );
  }

  const connector = connectorQuery.data;
  const issueCount = Array.isArray(connector.issues)
    ? connector.issues.length
    : 0;

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title={connector.connectorId}
        breadcrumbs={[
          { label: "Machine Identity" },
          { label: "Connectors", href: CONNECTORS_HREF },
        ]}
        subtitle={<CaConnectorLabel caProvider={connector.caProvider} />}
        badge={{
          label: humanizeConstant(connector.status),
          variant: caConnectorStatusVariant(connector.status),
        }}
      />

      {!connector.enabled ? (
        <ModuleNotice tone="warning">
          This connector is disabled, so CertPing will not route issuance to it.
          Certificates it already issued stay in the inventory.
        </ModuleNotice>
      ) : null}

      {connector.stale ? (
        <ModuleNotice tone="warning">
          The last health report arrived{" "}
          {formatDateTimeCompact(connector.receivedAt)} and is now considered
          stale, so the agent that reports this connector may be stopped or
          removed. It last reported{" "}
          {humanizeConstant(connector.reportedStatus).toLowerCase()}.
        </ModuleNotice>
      ) : null}

      {issueCount > 0 ? (
        <ModuleNotice
          tone={connector.status === "HEALTHY" ? "warning" : "danger"}
        >
          {issueCount === 1
            ? "The CA reported 1 issue in its last health check. It is listed under Issues below."
            : `The CA reported ${issueCount} issues in its last health check. They are listed under Issues below.`}
        </ModuleNotice>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
        <DetailPanel title="Connection">
          <dl className="divide-y divide-border">
            <DetailRow
              label="Connector ID"
              value={connector.connectorId}
              monospace
              copyable
            />
            <DetailRow
              label="CA provider"
              node={<CaConnectorLabel caProvider={connector.caProvider} />}
            />
            <DetailRow
              label="Enabled"
              node={
                <Badge variant={connector.enabled ? "success" : "secondary"}>
                  {connector.enabled ? "Enabled" : "Disabled"}
                </Badge>
              }
            />
            <DetailRow label="Endpoint" value={connector.endpoint} monospace />
            <DetailRow
              label="Auth method"
              value={
                connector.authMethod
                  ? humanizeConstant(connector.authMethod)
                  : null
              }
            />
            <DetailRow
              label="Capabilities"
              node={
                connector.capabilities.length === 0 ? (
                  <span className="text-muted-foreground">None advertised</span>
                ) : (
                  <span className="flex flex-wrap gap-1">
                    {connector.capabilities.map((capability) => (
                      <Badge key={capability} variant="secondary">
                        {humanizeConstant(capability)}
                      </Badge>
                    ))}
                  </span>
                )
              }
            />
          </dl>
        </DetailPanel>

        <DetailPanel title="Health">
          <dl className="divide-y divide-border">
            <DetailRow
              label="Status"
              node={
                <Badge variant={caConnectorStatusVariant(connector.status)}>
                  {humanizeConstant(connector.status)}
                </Badge>
              }
            />
            <DetailRow
              label="Latency"
              value={
                connector.latencyMs != null
                  ? `${connector.latencyMs.toLocaleString()} ms`
                  : null
              }
            />
            <DetailRow
              label="Checked"
              value={formatDateTimeCompact(connector.checkedAt)}
            />
            <DetailRow
              label="Responded"
              value={
                connector.respondedAt
                  ? formatDateTimeCompact(connector.respondedAt)
                  : null
              }
            />
            <DetailRow
              label="Received"
              value={formatDateTimeCompact(connector.receivedAt)}
            />
            <DetailRow
              label="Report version"
              value={String(connector.reportVersion)}
            />
          </dl>
        </DetailPanel>
      </div>

      {/*
        Two balanced columns, not three fixed ones: the CA's Issues payload is
        usually a single line while its Profiles payload is a dozen, so a
        three-column grid left two thirds of the row empty.
      */}
      <PanelMasonry>
        <DynamicDataPanel
          title="Product"
          description="What the CA reports about itself."
          value={connector.product}
          emptyMessage="The CA reported no product details."
        />
        <DynamicDataPanel
          title="Profiles"
          description="Issuance profiles the CA exposes."
          value={connector.profiles}
          emptyMessage="The CA exposed no issuance profiles."
        />
        <DynamicDataPanel
          title="Issues"
          description="Problems found by the last health check."
          value={connector.issues}
          emptyMessage="The last health check found no issues."
        />
      </PanelMasonry>
    </div>
  );
}
