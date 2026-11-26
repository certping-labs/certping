// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { use, useState } from "react";
import {
  FunnelIcon,
  CircleNotchIcon,
  PauseCircleIcon,
  ArrowsClockwiseIcon,
} from "@phosphor-icons/react";

import {
  DetailEmptyState,
  DetailPanel,
  DetailRow,
  DynamicDataPanel,
  PanelMasonry,
} from "@/components/machine-identity/detail-panel";
import { DeviceEventList } from "@/components/machine-identity/device-event-list";
import { DeviceSourcePermissions } from "@/components/machine-identity/device-source-permissions";
import { ModuleNotice } from "@/components/machine-identity/module-notice";
import { ProviderLabel } from "@/components/machine-identity/provider-label";
import { MachineIdentityQueryErrorState } from "@/components/machine-identity/query-error-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useDeviceSource,
  useDeviceSourceEvents,
  useStopDeviceSourceSync,
  useTriggerDeviceSourceSync,
} from "@/hooks/machine-identity/use-device-sources";
import { usePermissions } from "@/hooks/use-permissions";
import { PERMISSIONS } from "@/lib/authz";
import {
  scepEnrollmentPath,
  sourceHealthVariant,
  sourceSyncStatusVariant,
} from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";

const CONNECTORS_HREF = "/integrations/device-sources";
const EVENT_PAGE_SIZE = 25;

export default function DeviceSourceDetailPage({
  params,
}: {
  params: Promise<{ sourceXref: string }>;
}) {
  const { sourceXref } = use(params);
  const [eventPage, setEventPage] = useState(0);
  const [isScopedToLatestRun, setIsScopedToLatestRun] = useState(false);

  const sourceQuery = useDeviceSource(sourceXref);
  const latestSyncXref = sourceQuery.data?.sync?.syncXref;
  /**
   * Every sync run gets its own `syncXref`, and the source-event endpoint
   * accepts it as a `correlationId`. Scoping the feed to it turns a mixed
   * audit log into the story of one run - which is what an operator watching
   * a sync they just started actually wants.
   */
  const eventsQuery = useDeviceSourceEvents(sourceXref, {
    page: eventPage,
    size: EVENT_PAGE_SIZE,
    correlationId:
      isScopedToLatestRun && latestSyncXref ? latestSyncXref : undefined,
  });
  const triggerSync = useTriggerDeviceSourceSync();
  const stopSync = useStopDeviceSourceSync();
  const { can } = usePermissions();
  const canManageSources = can(PERMISSIONS.iotSourceManage);

  if (sourceQuery.isLoading) {
    return (
      <div className="space-y-4 p-4 md:p-6">
        <Skeleton className="h-16 w-full max-w-xl" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (sourceQuery.error || !sourceQuery.data) {
    return (
      <div className="p-4 md:p-6">
        {/* There is no single-source GET; the record is found in the cached
            list. A successful list that does not contain this xref means the
            source is genuinely gone, not that the request failed. */}
        <MachineIdentityQueryErrorState
          error={sourceQuery.error}
          title="Unable to load device source"
          description="This device source could not be loaded."
          resourceLabel="device source"
          backHref={CONNECTORS_HREF}
          backLabel="Back to connectors"
          onRetry={() => void sourceQuery.refetch()}
          isRetrying={sourceQuery.isFetching}
        />
      </div>
    );
  }

  const source = sourceQuery.data;
  const sync = source.sync;
  // The backend lifts `permissions` out of the health metadata blob, so it is
  // not in `metadata` and has nowhere else to be rendered.
  const permissions = source.health?.permissions ?? [];
  const missingPermissions = permissions.filter(
    (permission) => !permission.granted,
  );
  const isSyncing =
    sync?.status === "PENDING" ||
    sync?.status === "RUNNING" ||
    triggerSync.isPending;
  const eventsPage = eventsQuery.data;

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title={source.displayName}
        breadcrumbs={[
          { label: "Machine Identity" },
          { label: "Connectors", href: CONNECTORS_HREF },
        ]}
        subtitle={<ProviderLabel provider={source.provider} />}
        badge={
          source.health
            ? {
                label: humanizeConstant(source.health.status),
                variant: sourceHealthVariant(source.health.status),
              }
            : { label: "No health report", variant: "secondary" }
        }
        actions={
          !canManageSources ? null : (
            <div className="flex flex-wrap items-center gap-2">
              {source.syncEnabled ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => stopSync.mutate(source.sourceXref)}
                  disabled={stopSync.isPending}
                >
                  <PauseCircleIcon className="size-4" aria-hidden="true" />
                  Stop schedule
                </Button>
              ) : null}
              <Button
                size="sm"
                onClick={() => triggerSync.mutate(source.sourceXref)}
                disabled={isSyncing}
              >
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
            </div>
          )
        }
      />

      {!source.syncEnabled ? (
        <ModuleNotice tone="warning">
          Scheduled syncs are off for this source. Its device inventory will not
          refresh until someone runs a sync, which also re-enables the hourly
          schedule.
        </ModuleNotice>
      ) : null}

      {source.health?.stale ? (
        <ModuleNotice tone="warning">
          The last health report arrived{" "}
          {formatDateTimeCompact(source.health.receivedAt)} and is now
          considered stale, so the status above may not reflect the agent&apos;s
          current state.
        </ModuleNotice>
      ) : null}

      {source.provider === "INTUNE" && missingPermissions.length > 0 ? (
        <ModuleNotice tone="warning">
          {missingPermissions.length} Microsoft Graph permission
          {missingPermissions.length === 1 ? " is" : "s are"} missing. Device
          inventory may still work, but the affected certificate actions are
          unavailable until an administrator grants consent.
        </ModuleNotice>
      ) : null}

      {sync?.lastError ? (
        <ModuleNotice tone="danger">
          Last sync reported: {sync.lastError}
        </ModuleNotice>
      ) : null}

      <PanelMasonry>
        <DetailPanel title="Connection">
          <dl className="divide-y divide-border">
            <DetailRow
              label="Category"
              value={humanizeConstant(source.sourceCategory)}
            />
            <DetailRow
              label="Connection ref"
              value={source.connectionProfileRef}
              monospace
              copyable
            />
            {/*
              Endpoint-management sources enroll devices over SCEP, and the MDM
              profile needs this path. Cloud IoT registries do not enroll this
              way, so for them the row would be a misleading copy target.
            */}
            {source.sourceCategory === "ENDPOINT_MANAGEMENT" ? (
              <DetailRow
                label="SCEP endpoint"
                value={scepEnrollmentPath(source.connectionProfileRef)}
                node={
                  <span className="flex flex-col gap-0.5">
                    <span className="font-mono text-xs wrap-anywhere wrap-break-word">
                      {scepEnrollmentPath(source.connectionProfileRef)}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      Prefix with your agent&apos;s own base URL. The agent may
                      only be reachable inside your network, so CertPing cannot
                      know its host.
                    </span>
                  </span>
                }
                copyable
              />
            ) : null}
            <DetailRow label="Description" value={source.description} />
            <DetailRow
              label="Status"
              node={
                <Badge
                  variant={source.status === "ACTIVE" ? "success" : "secondary"}
                >
                  {humanizeConstant(source.status)}
                </Badge>
              }
            />
            <DetailRow
              label="Scheduled sync"
              node={
                <Badge variant={source.syncEnabled ? "success" : "warning"}>
                  {source.syncEnabled ? "Hourly" : "Stopped"}
                </Badge>
              }
            />
            <DetailRow
              label="Devices"
              value={source.deviceCount.toLocaleString()}
            />
            <DetailRow
              label="First advertised"
              value={formatDateTimeCompact(source.firstAdvertisedAt)}
            />
            <DetailRow
              label="Last advertised"
              value={formatDateTimeCompact(source.lastAdvertisedAt)}
            />
          </dl>
        </DetailPanel>

        <DynamicDataPanel
          title="Advertised configuration"
          description="Non-secret settings the agent reports for this connection."
          value={source.configurationMetadata}
          emptyMessage="This source advertised no configuration metadata."
        />

        <DetailPanel title="Health">
          {source.health ? (
            <dl className="divide-y divide-border">
              <DetailRow
                label="Effective status"
                node={
                  <Badge variant={sourceHealthVariant(source.health.status)}>
                    {humanizeConstant(source.health.status)}
                  </Badge>
                }
              />
              <DetailRow
                label="Reported status"
                value={humanizeConstant(source.health.reportedStatus)}
              />
              <DetailRow
                label="Provider status"
                value={source.health.providerStatus}
              />
              <DetailRow label="Message" value={source.health.statusMessage} />
              <DetailRow
                label="Response time"
                value={
                  source.health.responseTimeMs != null
                    ? `${source.health.responseTimeMs.toLocaleString()} ms`
                    : null
                }
              />
              <DetailRow
                label="Observed"
                value={formatDateTimeCompact(source.health.observedAt)}
              />
              <DetailRow
                label="Received"
                value={formatDateTimeCompact(source.health.receivedAt)}
              />
              <DetailRow
                label="Goes stale"
                value={formatDateTimeCompact(source.health.staleAt)}
              />
            </dl>
          ) : (
            <DetailEmptyState message="This source has not reported health yet. It appears in the list from its first advertisement, but health arrives with the agent's first probe." />
          )}
        </DetailPanel>

        {source.provider === "INTUNE" ? (
          <DetailPanel
            title="Microsoft Graph permissions"
            description="Application permissions observed in the access token and verified by the latest agent health check."
            headerAccessory={
              missingPermissions.length > 0 ? (
                <Badge variant="destructive">
                  {missingPermissions.length} missing
                </Badge>
              ) : null
            }
          >
            <DeviceSourcePermissions permissions={permissions} />
          </DetailPanel>
        ) : null}

        <DetailPanel title="Latest sync">
          {sync ? (
            <dl className="divide-y divide-border">
              <DetailRow
                label="Status"
                node={
                  <Badge variant={sourceSyncStatusVariant(sync.status)}>
                    {humanizeConstant(sync.status)}
                  </Badge>
                }
              />
              <DetailRow label="Run" value={sync.syncXref} monospace copyable />
              <DetailRow
                label="Requested"
                value={formatDateTimeCompact(sync.requestedAt)}
              />
              <DetailRow
                label="Started"
                value={
                  sync.startedAt ? formatDateTimeCompact(sync.startedAt) : null
                }
              />
              <DetailRow
                label="Completed"
                value={
                  sync.completedAt
                    ? formatDateTimeCompact(sync.completedAt)
                    : sync.completionReceived
                      ? "Completion received, closing"
                      : null
                }
              />
              <DetailRow
                label="Devices"
                value={`${(sync.processedDeviceCount ?? 0).toLocaleString()} processed${
                  sync.expectedDeviceCount != null
                    ? ` of ${sync.expectedDeviceCount.toLocaleString()} expected`
                    : ""
                }`}
              />
              <DetailRow
                label="Devices failed"
                value={(sync.failedDeviceCount ?? 0).toLocaleString()}
              />
              <DetailRow
                label="Batches"
                value={`${(sync.processedBatchCount ?? 0).toLocaleString()}${
                  sync.expectedBatchCount != null
                    ? ` of ${sync.expectedBatchCount.toLocaleString()}`
                    : ""
                }`}
              />
            </dl>
          ) : (
            <DetailEmptyState message="No sync has run for this source yet." />
          )}
        </DetailPanel>

        <DynamicDataPanel
          title="Health metadata"
          description="Extra facts the agent attached to its last health report."
          value={source.health?.metadata}
          emptyMessage="The last health report carried no metadata."
        />
      </PanelMasonry>

      <DetailPanel
        title="Activity"
        description={
          isScopedToLatestRun
            ? "Newest first, limited to the latest sync run."
            : "Newest first."
        }
        headerAccessory={
          <div className="flex items-center gap-2">
            {sync?.syncXref ? (
              <Button
                // Both states are buttons: `ghost` rendered the inactive state
                // as bare text, which read as a caption rather than a control.
                variant={isScopedToLatestRun ? "secondary" : "outline"}
                size="sm"
                aria-pressed={isScopedToLatestRun}
                onClick={() => {
                  setIsScopedToLatestRun((scoped) => !scoped);
                  setEventPage(0);
                }}
              >
                <FunnelIcon className="size-4" aria-hidden="true" />
                {isScopedToLatestRun ? "All activity" : "Latest sync run only"}
              </Button>
            ) : null}
            {eventsPage ? (
              <Badge variant="secondary">
                {eventsPage.totalElements.toLocaleString()} events
              </Badge>
            ) : null}
          </div>
        }
      >
        {eventsQuery.error ? (
          <MachineIdentityQueryErrorState
            className="border-0"
            error={eventsQuery.error}
            title="Unable to load activity"
            description="This source's history could not be loaded."
            onRetry={() => void eventsQuery.refetch()}
            isRetrying={eventsQuery.isFetching}
          />
        ) : (
          <>
            <DeviceEventList
              events={eventsPage?.content.map((event) => ({
                eventXref: event.eventXref,
                eventType: event.eventType,
                eventStatus: event.eventStatus,
                eventMessage: null,
                // Source events describe server/agent machinery, never a user
                // action, so there is no actor on the wire to render.
                actorSource: "SYSTEM",
                actorUserId: null,
                correlationId: event.correlationId,
                detail: event.detail,
                occurredAt: event.occurredAt,
              }))}
              isLoading={eventsQuery.isLoading}
              emptyMessage={
                isScopedToLatestRun
                  ? "The latest sync run has not recorded any events yet."
                  : "No activity recorded for this source."
              }
            />
            {eventsPage && eventsPage.totalPages > 1 ? (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-2.5">
                <span className="text-xs text-muted-foreground">
                  Page {eventsPage.number + 1} of {eventsPage.totalPages}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={eventsPage.first || eventsQuery.isFetching}
                    onClick={() =>
                      setEventPage((current) => Math.max(0, current - 1))
                    }
                  >
                    Newer
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={eventsPage.last || eventsQuery.isFetching}
                    onClick={() => setEventPage((current) => current + 1)}
                  >
                    Older
                  </Button>
                </div>
              </div>
            ) : null}
          </>
        )}
      </DetailPanel>
    </div>
  );
}
