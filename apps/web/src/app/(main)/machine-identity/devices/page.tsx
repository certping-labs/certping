// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  ProhibitIcon,
  StackIcon,
  ShieldCheckIcon,
  ShieldSlashIcon,
} from "@phosphor-icons/react";

import {
  buildDeviceColumns,
  DEVICE_DEFAULT_HIDDEN_COLUMNS,
} from "@/components/machine-identity/device-columns";
import { FilterBar } from "@/components/machine-identity/filter-bar";
import { FleetPosturePanels } from "@/components/machine-identity/fleet-posture-panels";
import {
  InventoryStatCards,
  type InventoryStatCard,
} from "@/components/machine-identity/inventory-stat-cards";
import { ModuleNotice } from "@/components/machine-identity/module-notice";
import { PaginatedTableCard } from "@/components/machine-identity/paginated-table-card";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { useListControls } from "@/hooks/machine-identity/use-list-controls";
import { useDeviceSources } from "@/hooks/machine-identity/use-device-sources";
import {
  useDeviceCount,
  useDevices,
} from "@/hooks/machine-identity/use-machine-devices";
import { useIotSummary } from "@/hooks/machine-identity/use-machine-identity-summary";
import {
  COMPLIANCE_STATE_LABELS,
  DEVICE_STATUS_LABELS,
} from "@/lib/machine-identity/backend-display";
import { asEnumValue, toSelectOptions } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";
import type {
  DeviceListItem,
  DeviceStatus,
} from "@/types/machine-identity-backend";

const DEVICE_STATUS_OPTIONS = toSelectOptions(DEVICE_STATUS_LABELS);
const COMPLIANCE_OPTIONS = toSelectOptions(COMPLIANCE_STATE_LABELS);

interface DeviceFilters extends Record<string, string | undefined> {
  /**
   * A `sourceXref`, not a provider constant. `GET /api/v1/iot/devices` resolves
   * `source` through `findBySourceXrefAndOrganizationId` and 404s the whole
   * request when it does not match, so the options must come from the live
   * source list rather than from the provider enum.
   */
  source: string | undefined;
  status: string | undefined;
  os: string | undefined;
  complianceState: string | undefined;
}

const DEFAULT_FILTERS: DeviceFilters = {
  source: undefined,
  status: undefined,
  os: undefined,
  complianceState: undefined,
};

export default function MachineIdentityDevicesPage() {
  const router = useRouter();
  const controls = useListControls<DeviceFilters>(DEFAULT_FILTERS);
  const { filters, setFilter } = controls;

  const summaryQuery = useIotSummary();
  const sourcesQuery = useDeviceSources();

  const summary = summaryQuery.data;
  const sources = useMemo(() => sourcesQuery.data ?? [], [sourcesQuery.data]);

  /**
   * Filters round-trip through the URL, so these values are untrusted. The
   * backend binds `status` and `complianceState` to enums and resolves
   * `source` to a real `sourceXref`, rejecting anything else with a 400 or a
   * 404 that takes the whole table down - so a stale bookmark is normalized
   * here instead of being forwarded.
   */
  const status = asEnumValue(filters.status, DEVICE_STATUS_LABELS);
  const complianceState = asEnumValue(
    filters.complianceState,
    COMPLIANCE_STATE_LABELS,
  );
  const isKnownSource =
    filters.source !== undefined &&
    sources.some((source) => source.sourceXref === filters.source);
  const hasUnknownSourceFilter =
    filters.source !== undefined && sourcesQuery.isSuccess && !isKnownSource;

  const devicesQuery = useDevices(
    {
      page: controls.page,
      size: controls.pageSize,
      search: controls.search,
      source: isKnownSource ? filters.source : undefined,
      status,
      os: filters.os,
      complianceState,
    },
    // A source filter is only meaningful once the source list has arrived;
    // firing before then would either drop the filter for one render or send
    // an xref that may not exist.
    { enabled: filters.source === undefined || sourcesQuery.isSuccess },
  );

  /**
   * Counts for the tiles, scoped to every filter except `status` - so each
   * tile is exactly "the table below, plus this status" and the four of them
   * add up to the All devices tile.
   *
   * <p>Unfiltered, that is precisely what `GET /iot/summary` already returns,
   * in one request that this page fetches anyway for the posture panels. Four
   * extra count queries are only worth their requests once a filter makes the
   * summary describe a different population than the table.
   */
  const countScope = {
    source: isKnownSource ? filters.source : undefined,
    os: filters.os,
    complianceState,
    search: controls.search,
  };
  const isScoped = Boolean(
    countScope.source ||
    countScope.os ||
    countScope.complianceState ||
    countScope.search,
  );
  const countsEnabled =
    isScoped && (filters.source === undefined || sourcesQuery.isSuccess);
  const totalCount = useDeviceCount(countScope, { enabled: countsEnabled });
  const registeredCount = useDeviceCount(
    { ...countScope, status: "REGISTERED" },
    { enabled: countsEnabled },
  );
  const orphanedCount = useDeviceCount(
    { ...countScope, status: "ORPHANED" },
    { enabled: countsEnabled },
  );
  const decommissionedCount = useDeviceCount(
    { ...countScope, status: "DECOMMISSIONED" },
    { enabled: countsEnabled },
  );

  const byStatus = summary?.byStatus ?? {};
  const tileCounts = isScoped
    ? {
        total: totalCount.data,
        registered: registeredCount.data,
        orphaned: orphanedCount.data,
        decommissioned: decommissionedCount.data,
        isLoading: totalCount.isLoading,
        hasError:
          totalCount.isError ||
          registeredCount.isError ||
          orphanedCount.isError ||
          decommissionedCount.isError,
      }
    : {
        total: summary?.totalDevices,
        registered: byStatus.REGISTERED,
        orphaned: byStatus.ORPHANED,
        decommissioned: byStatus.DECOMMISSIONED,
        isLoading: summaryQuery.isLoading,
        hasError: summaryQuery.isError,
      };

  const sourceOptions = useMemo(
    () =>
      sources.map((source) => ({
        value: source.sourceXref,
        label: source.displayName,
      })),
    [sources],
  );

  /**
   * The list endpoint takes a free-text `os`, so the choices come from the
   * summary's own operating-system breakdown rather than a hardcoded list -
   * whatever the sources actually reported is exactly what is offered. The
   * "UNKNOWN" bucket is dropped: there is no "operating system is null" filter
   * to send.
   */
  const operatingSystemOptions = useMemo(
    () =>
      Object.entries(summary?.byOperatingSystem ?? {})
        .filter(([key, count]) => key !== "UNKNOWN" && count > 0)
        .sort((left, right) => right[1] - left[1])
        .map(([key]) => ({ value: key, label: key })),
    [summary?.byOperatingSystem],
  );

  const providerByDisplayName = useMemo(() => {
    const byDisplayName = new Map<string, string>();
    for (const source of sources) {
      byDisplayName.set(source.displayName, source.provider);
    }
    return byDisplayName;
  }, [sources]);

  const columns = useMemo(
    () => buildDeviceColumns({ providerByDisplayName }),
    [providerByDisplayName],
  );

  const toggleStatus = useCallback(
    (next: DeviceStatus) => {
      setFilter("status", status === next ? undefined : next);
    },
    [status, setFilter],
  );

  const statCards: InventoryStatCard[] = [
    {
      key: "total",
      title: "All devices",
      value: tileCounts.total ?? 0,
      description: "Every status",
      icon: StackIcon,
      tone: "primary",
      onClick: () => setFilter("status", undefined),
      isActive: status === undefined,
      hasError: tileCounts.hasError,
    },
    {
      key: "registered",
      title: "Registered",
      value: tileCounts.registered ?? 0,
      description: "Currently in the source",
      icon: ShieldCheckIcon,
      tone: "success",
      onClick: () => toggleStatus("REGISTERED"),
      isActive: status === "REGISTERED",
      hasError: tileCounts.hasError,
    },
    {
      key: "orphaned",
      title: "Orphaned",
      value: tileCounts.orphaned ?? 0,
      description: "Gone from the source",
      icon: ShieldSlashIcon,
      tone: (tileCounts.orphaned ?? 0) > 0 ? "warning" : "neutral",
      onClick: () => toggleStatus("ORPHANED"),
      isActive: status === "ORPHANED",
      hasError: tileCounts.hasError,
    },
    {
      key: "decommissioned",
      title: "Decommissioned",
      value: tileCounts.decommissioned ?? 0,
      description: "Retired in CertPing",
      icon: ProhibitIcon,
      tone: "neutral",
      onClick: () => toggleStatus("DECOMMISSIONED"),
      isActive: status === "DECOMMISSIONED",
      hasError: tileCounts.hasError,
    },
  ];

  const shownDevices = devicesQuery.data?.totalElements;

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title="Devices"
        breadcrumbs={[{ label: "Machine Identity" }]}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>
              Every device your connected sources report, including devices that
              have since disappeared from their source.
            </span>
            {summary?.lastSyncCompletedAt ? (
              <>
                <span aria-hidden="true">·</span>
                <span className="whitespace-nowrap">
                  Last sync {formatDateTimeCompact(summary.lastSyncCompletedAt)}
                </span>
              </>
            ) : null}
          </span>
        }
        badge={
          shownDevices === undefined
            ? undefined
            : {
                label: `${shownDevices.toLocaleString()} shown`,
                variant: "secondary",
              }
        }
      />

      {hasUnknownSourceFilter ? (
        <ModuleNotice
          tone="info"
          action={
            <Button
              variant="outline"
              size="sm"
              onClick={() => setFilter("source", undefined)}
            >
              Clear filter
            </Button>
          }
        >
          The device source in this link is no longer advertised, so every
          device is shown instead.
        </ModuleNotice>
      ) : null}

      <InventoryStatCards
        cards={statCards}
        isLoading={summaryQuery.isLoading}
      />

      <FleetPosturePanels
        summary={summary}
        isLoading={summaryQuery.isLoading}
        onSelectOperatingSystem={(value) => setFilter("os", value)}
        activeOperatingSystem={filters.os}
        onSelectCompliance={(value) => setFilter("complianceState", value)}
        activeCompliance={complianceState}
      />

      <PaginatedTableCard<DeviceListItem>
        columns={columns}
        page={devicesQuery.data}
        isLoading={devicesQuery.isPending}
        isFetching={devicesQuery.isFetching}
        error={devicesQuery.error}
        errorTitle="Unable to load devices"
        errorDescription="The device inventory could not be loaded."
        emptyMessage="No devices match the current filters."
        minWidthClassName="min-w-304"
        defaultHiddenColumns={DEVICE_DEFAULT_HIDDEN_COLUMNS}
        toolbar={
          <FilterBar
            searchValue={controls.searchInput}
            onSearchChange={controls.setSearchInput}
            searchPlaceholder="Search by device name or serial number"
            filters={[
              {
                id: "source",
                label: "Source",
                value: isKnownSource ? filters.source : undefined,
                options: sourceOptions,
                onChange: (value) => setFilter("source", value),
                emptyMessage: "No device sources have been advertised yet.",
              },
              {
                id: "status",
                label: "Status",
                value: status,
                options: DEVICE_STATUS_OPTIONS,
                onChange: (value) => setFilter("status", value),
              },
              {
                id: "complianceState",
                label: "Compliance",
                value: complianceState,
                options: COMPLIANCE_OPTIONS,
                onChange: (value) => setFilter("complianceState", value),
              },
              {
                id: "os",
                label: "Operating system",
                value: filters.os,
                options: operatingSystemOptions,
                onChange: (value) => setFilter("os", value),
                emptyMessage: "No source has reported an operating system yet.",
              },
            ]}
          />
        }
        onRetry={() => void devicesQuery.refetch()}
        isRetrying={devicesQuery.isFetching}
        getRowId={(device) => device.deviceXref}
        onRowClick={(device) =>
          router.push(`/machine-identity/devices/${device.deviceXref}`)
        }
        onPageChange={controls.setPage}
        onPageSizeChange={controls.setPageSize}
      />
    </div>
  );
}
