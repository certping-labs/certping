// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { IntegrationsTabHeader } from "@/components/integrations/integrations-tab-header";
import { CaConnectorRow } from "@/components/machine-identity/ca-connector-row";
import { DeviceSourceRow } from "@/components/machine-identity/device-source-row";
import { MachineIdentityQueryErrorState } from "@/components/machine-identity/query-error-state";
import { Skeleton } from "@/components/ui/skeleton";
import { useCaConnectors } from "@/hooks/machine-identity/use-ca-connectors";
import {
  useDeviceSources,
  useStopDeviceSourceSync,
  useTriggerDeviceSourceSync,
} from "@/hooks/machine-identity/use-device-sources";
import { usePermissions } from "@/hooks/use-permissions";
import { PERMISSIONS } from "@/lib/authz";

/**
 * The two Integrations categories nobody connects from the console.
 *
 * A CA or a device source appears once a deployed agent sends its first health
 * report, so these categories have no Add button - the "Auto-discovered" badge
 * and the empty state say so before the user goes hunting for one.
 */

const AUTO_DISCOVERED_NOTE =
  "These appear automatically once a CertPing agent sends its first health check - there is nothing to configure here.";

export function CertificateAuthoritiesPanel({
  title = "Certificate authorities",
}: {
  title?: string;
} = {}) {
  const caConnectorsQuery = useCaConnectors();
  const caConnectors = caConnectorsQuery.data ?? [];

  // Derived from the list already on screen rather than a second summary
  // request - the same numbers, one round trip fewer.
  const enabledConnectors = caConnectors.filter(
    (connector) => connector.enabled,
  ).length;

  return (
    <div className="space-y-4">
      <IntegrationsTabHeader
        title={title}
        autoDiscovered
        description={`Where your device certificates are issued, and whether each CA is accepting issuance. ${AUTO_DISCOVERED_NOTE}`}
      />

      <AgentAdvertisedList
        summary={
          caConnectors.length === 0
            ? null
            : `${caConnectors.length} advertised · ${enabledConnectors} accepting issuance`
        }
        isLoading={caConnectorsQuery.isLoading}
        error={caConnectorsQuery.error}
        errorTitle="Unable to load certificate authorities"
        errorDescription="Certificate authority connectors could not be loaded."
        onRetry={() => void caConnectorsQuery.refetch()}
        isRetrying={caConnectorsQuery.isFetching}
        isEmpty={caConnectors.length === 0}
        emptyMessage="No certificate authority has reported in yet. A CA appears here once an agent sends its first health report."
        skeletonCount={1}
      >
        {caConnectors.map((connector) => (
          <CaConnectorRow key={connector.connectorId} connector={connector} />
        ))}
      </AgentAdvertisedList>
    </div>
  );
}

export function DeviceSourcesPanel() {
  const sourcesQuery = useDeviceSources();
  const triggerSync = useTriggerDeviceSourceSync();
  const stopSync = useStopDeviceSourceSync();
  const { can } = usePermissions();
  const canManageSources = can(PERMISSIONS.iotSourceManage);

  const sources = sourcesQuery.data ?? [];
  const scheduledSources = sources.filter(
    (source) => source.syncEnabled,
  ).length;

  return (
    <div className="space-y-4">
      <IntegrationsTabHeader
        title="Device sources"
        autoDiscovered
        description={`The inventories your agents sync devices from, and how each sync is running. ${AUTO_DISCOVERED_NOTE}`}
      />

      <AgentAdvertisedList
        summary={
          sources.length === 0
            ? null
            : `${sources.length} advertised · ${scheduledSources} on the hourly schedule`
        }
        isLoading={sourcesQuery.isLoading}
        error={sourcesQuery.error}
        errorTitle="Unable to load device sources"
        errorDescription="Device sources could not be loaded."
        onRetry={() => void sourcesQuery.refetch()}
        isRetrying={sourcesQuery.isFetching}
        isEmpty={sources.length === 0}
        emptyMessage="No device source has advertised itself yet. Deploy a CertPing agent with a device-platform connection and it will appear here."
        skeletonCount={2}
      >
        {sources.map((source) => (
          <DeviceSourceRow
            key={source.sourceXref}
            source={source}
            isSyncing={
              source.sync?.status === "PENDING" ||
              source.sync?.status === "RUNNING" ||
              (triggerSync.isPending &&
                triggerSync.variables === source.sourceXref)
            }
            canManageSync={canManageSources}
            onSync={() => triggerSync.mutate(source.sourceXref)}
            onStopSync={() => stopSync.mutate(source.sourceXref)}
            isStoppingSync={
              stopSync.isPending && stopSync.variables === source.sourceXref
            }
          />
        ))}
      </AgentAdvertisedList>
    </div>
  );
}

interface AgentAdvertisedListProps {
  summary: string | null;
  isLoading: boolean;
  error: unknown;
  errorTitle: string;
  errorDescription: string;
  onRetry: () => void;
  isRetrying: boolean;
  isEmpty: boolean;
  emptyMessage: string;
  skeletonCount: number;
  children: React.ReactNode;
}

/**
 * Loading, error, empty and populated states for one agent-advertised list.
 *
 * The two categories are independent queries behind independent permissions,
 * so each owns its own error state - a single shared top-level error return
 * used to blank out the healthy one alongside the failing one.
 */
function AgentAdvertisedList({
  summary,
  isLoading,
  error,
  errorTitle,
  errorDescription,
  onRetry,
  isRetrying,
  isEmpty,
  emptyMessage,
  skeletonCount,
  children,
}: AgentAdvertisedListProps) {
  return (
    <section className="space-y-3">
      {summary ? (
        <p className="text-xs text-muted-foreground">{summary}</p>
      ) : null}

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: skeletonCount }, (_, index) => (
            <Skeleton key={index} className="h-28 w-full" />
          ))}
        </div>
      ) : error ? (
        <MachineIdentityQueryErrorState
          error={error}
          title={errorTitle}
          description={errorDescription}
          onRetry={onRetry}
          isRetrying={isRetrying}
        />
      ) : isEmpty ? (
        <p className="rounded-lg border border-dashed border-border bg-card px-6 py-10 text-center text-sm text-muted-foreground">
          {emptyMessage}
        </p>
      ) : (
        <div className="space-y-3">{children}</div>
      )}
    </section>
  );
}
