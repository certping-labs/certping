// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { use, useState } from "react";
import {
  ArchiveIcon,
  ArrowCounterClockwiseIcon,
  BellRingingIcon,
  CircleNotchIcon,
  ShieldSlashIcon,
} from "@phosphor-icons/react";

import {
  DeviceIdentityPanels,
  DevicePlatformDataPanels,
  DevicePosturePanels,
} from "@/components/machine-identity/device-detail-panels";
import {
  DetailPanel,
  PanelMasonry,
} from "@/components/machine-identity/detail-panel";
import { DeviceCertificatesTab } from "@/components/machine-identity/device-certificates-tab";
import { DeviceEventList } from "@/components/machine-identity/device-event-list";
import { ProviderLabel } from "@/components/machine-identity/provider-label";
import { MachineIdentityQueryErrorState } from "@/components/machine-identity/query-error-state";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  useArchiveDevice,
  useDecommissionDevice,
  useDevice,
  useDeviceEvents,
  useRestoreDevice,
} from "@/hooks/machine-identity/use-machine-devices";
import { useRequestCertificateDeviceSync } from "@/hooks/machine-identity/use-machine-certificates";
import { usePermissions } from "@/hooks/use-permissions";
import { PERMISSIONS } from "@/lib/authz";
import {
  DEVICE_STATUS_LABELS,
  deviceStatusVariant,
} from "@/lib/machine-identity/backend-display";

const DEVICES_HREF = "/machine-identity/devices";
const EVENT_PAGE_SIZE = 25;

export default function DeviceDetailPage({
  params,
}: {
  params: Promise<{ deviceXref: string }>;
}) {
  const { deviceXref } = use(params);
  const [eventPage, setEventPage] = useState(0);

  const deviceQuery = useDevice(deviceXref);
  const eventsQuery = useDeviceEvents(deviceXref, {
    page: eventPage,
    size: EVENT_PAGE_SIZE,
  });
  const decommissionDevice = useDecommissionDevice();
  const archiveDevice = useArchiveDevice();
  const restoreDevice = useRestoreDevice();
  const requestCheckIn = useRequestCertificateDeviceSync();
  const { can } = usePermissions();
  const canManageDevices = can(PERMISSIONS.iotDeviceManage);

  if (deviceQuery.isLoading) {
    return (
      <div className="space-y-4 p-4 md:p-6">
        <Skeleton className="h-16 w-full max-w-xl" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (deviceQuery.error || !deviceQuery.data) {
    return (
      <div className="p-4 md:p-6">
        <MachineIdentityQueryErrorState
          error={deviceQuery.error}
          title="Unable to load device"
          description="This device's record could not be loaded."
          resourceLabel="device"
          backHref={DEVICES_HREF}
          backLabel="Back to devices"
          onRetry={() => void deviceQuery.refetch()}
          isRetrying={deviceQuery.isFetching}
        />
      </div>
    );
  }

  const device = deviceQuery.data;
  const isDecommissioned = device.status === "DECOMMISSIONED";
  // Only an orphaned device may be archived: one its source still reports would simply come back
  // on the next sync, and the backend refuses it for that reason.
  const canArchive = device.status === "ORPHANED" && !device.archived;
  const eventsPage = eventsQuery.data;

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title={device.deviceName ?? "Unnamed device"}
        breadcrumbs={[
          { label: "Machine Identity" },
          { label: "Devices", href: DEVICES_HREF },
        ]}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <ProviderLabel provider={device.source.provider} />
            <span aria-hidden="true">·</span>
            <Link
              href={`/integrations/device-sources/${device.source.sourceXref}`}
              className="hover:text-foreground hover:underline"
            >
              {device.source.displayName}
            </Link>
            {/* An archived device is reachable by link but absent from the inventory. Saying so
            here stops the page reading as though the device were simply missing from search. */}
            {device.archived ? (
              <>
                <span aria-hidden="true">·</span>
                <Badge variant="outline" className="font-medium">
                  Archived — hidden from the inventory
                </Badge>
              </>
            ) : null}
          </span>
        }
        badge={
          device.status
            ? {
                label: DEVICE_STATUS_LABELS[device.status],
                variant: deviceStatusVariant(device.status),
              }
            : undefined
        }
        actions={
          !canManageDevices ? null : (
            <>
              {/* Only offered while the device is still live in its source: a
              decommissioned or orphaned device has nothing in Intune to check
              in, and the request would come back SKIPPED. */}
              {device.status === "REGISTERED" ? (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={requestCheckIn.isPending}
                  title="Asks Intune to contact this device so it renews sooner than its own schedule would. Intune decides when the device responds."
                  onClick={() =>
                    requestCheckIn.mutate({ deviceXrefs: [deviceXref] })
                  }
                >
                  {requestCheckIn.isPending ? (
                    <CircleNotchIcon
                      className="size-4 animate-spin"
                      aria-hidden="true"
                    />
                  ) : (
                    <BellRingingIcon className="size-4" aria-hidden="true" />
                  )}
                  Request check-in
                </Button>
              ) : null}
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={isDecommissioned}
                  >
                    <ShieldSlashIcon className="size-4" aria-hidden="true" />
                    {isDecommissioned ? "Decommissioned" : "Decommission"}
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>
                      Decommission {device.deviceName ?? "this device"}?
                    </AlertDialogTitle>
                    {/* Operators reasonably assume "decommission" reaches the MDM.
                    It does not, and the API has no scope to: saying so here is
                    the difference between a correct action and a false sense
                    that the device was retired or wiped. */}
                    <AlertDialogDescription>
                      This retires the device inside CertPing only. It is not
                      retired, wiped, or removed in {device.source.displayName},
                      and any certificate it already holds stays valid until it
                      is revoked or expires. History and certificates are kept
                      for the compliance window.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      variant="destructive"
                      disabled={decommissionDevice.isPending}
                      onClick={() => decommissionDevice.mutate(deviceXref)}
                    >
                      Decommission device
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
              {device.archived ? (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={restoreDevice.isPending}
                  onClick={() => restoreDevice.mutate(deviceXref)}
                >
                  {restoreDevice.isPending ? (
                    <CircleNotchIcon
                      className="size-4 animate-spin"
                      aria-hidden="true"
                    />
                  ) : (
                    <ArrowCounterClockwiseIcon
                      className="size-4"
                      aria-hidden="true"
                    />
                  )}
                  Restore to inventory
                </Button>
              ) : null}
              {canArchive ? (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="outline" size="sm">
                      <ArchiveIcon className="size-4" aria-hidden="true" />
                      Archive
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>
                        Archive {device.deviceName ?? "this device"}?
                      </AlertDialogTitle>
                      {/* "Archive" has to read as hiding, not deleting, or an
                      operator clears rows believing the certificate history
                      went with them. It did not, and on a PKI that distinction
                      is the whole point. */}
                      <AlertDialogDescription>
                        This takes the device out of the inventory. Nothing is
                        deleted: its certificates and history stay, and if{" "}
                        {device.source.displayName} reports the device again it
                        returns to the inventory on the next sync. A device that
                        still holds a valid certificate cannot be archived —
                        revoke it first.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        disabled={archiveDevice.isPending}
                        onClick={() => archiveDevice.mutate(deviceXref)}
                      >
                        Archive device
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              ) : null}
            </>
          )
        }
      />

      <Tabs defaultValue="details">
        {/* Four triggers are wider than a phone. Scrolling the strip keeps every
              tab reachable; wrapping it would put a two-line control block above
              content that is already tight. */}
        <TabsList variant="underline">
          <TabsTrigger value="details">Details</TabsTrigger>
          <TabsTrigger value="certificates">Certificates</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
          <TabsTrigger value="platform">Platform data</TabsTrigger>
        </TabsList>

        <TabsContent value="details" className="mt-3">
          <PanelMasonry>
            <DeviceIdentityPanels device={device} />
            <DevicePosturePanels device={device} />
          </PanelMasonry>
        </TabsContent>

        <TabsContent value="certificates" className="mt-3">
          <DeviceCertificatesTab deviceXref={deviceXref} />
        </TabsContent>

        <TabsContent value="activity" className="mt-3">
          <DetailPanel
            title="Activity"
            description="Newest first."
            headerAccessory={
              eventsPage ? (
                <Badge variant="secondary">
                  {eventsPage.totalElements.toLocaleString()} events
                </Badge>
              ) : null
            }
          >
            {eventsQuery.error ? (
              <MachineIdentityQueryErrorState
                className="border-0"
                error={eventsQuery.error}
                title="Unable to load activity"
                description="This device's history could not be loaded."
                onRetry={() => void eventsQuery.refetch()}
                isRetrying={eventsQuery.isFetching}
              />
            ) : (
              <>
                <DeviceEventList
                  events={eventsPage?.content}
                  isLoading={eventsQuery.isLoading}
                  emptyMessage="No activity recorded for this device."
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
        </TabsContent>

        <TabsContent value="platform" className="mt-3">
          <DevicePlatformDataPanels device={device} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
