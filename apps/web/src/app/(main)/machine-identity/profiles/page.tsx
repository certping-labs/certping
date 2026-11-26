// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ArchiveIcon,
  CheckCircleIcon,
  ClipboardTextIcon,
  StackIcon,
  CircleNotchIcon,
  PlusIcon,
  ArrowsClockwiseIcon,
} from "@phosphor-icons/react";

import { FilterBar } from "@/components/machine-identity/filter-bar";
import {
  InventoryStatCards,
  type InventoryStatCard,
} from "@/components/machine-identity/inventory-stat-cards";
import { PaginatedTableCard } from "@/components/machine-identity/paginated-table-card";
import { PROFILE_COLUMNS } from "@/components/machine-identity/profile-columns";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  useCertificateProfileCount,
  useCertificateProfiles,
  useSyncSourceProfiles,
} from "@/hooks/machine-identity/use-certificate-profiles";
import { useDeviceSources } from "@/hooks/machine-identity/use-device-sources";
import {
  PROFILE_CONTROL_MODE_LABELS,
  PROFILE_LIFECYCLE_LABELS,
  PROFILE_PROVIDER_SYNC_STATUS_LABELS,
} from "@/lib/machine-identity/backend-display";
import {
  humanizeConstant,
  toSelectOptions,
} from "@/lib/machine-identity/display";
import { useListControls } from "@/hooks/machine-identity/use-list-controls";
import { usePermissions } from "@/hooks/use-permissions";
import { PERMISSIONS } from "@/lib/authz";
import type {
  CertificateProfileResponse,
  ProfileControlMode,
  ProfileLifecycleStatus,
  ProfileProviderSyncStatus,
} from "@/types/machine-identity-backend";

const LIFECYCLE_OPTIONS = toSelectOptions(PROFILE_LIFECYCLE_LABELS);
const CONTROL_MODE_OPTIONS = toSelectOptions(PROFILE_CONTROL_MODE_LABELS);
const SYNC_STATUS_OPTIONS = toSelectOptions(
  PROFILE_PROVIDER_SYNC_STATUS_LABELS,
);

interface ProfileFilters extends Record<string, string | undefined> {
  lifecycleStatus: string | undefined;
  controlMode: string | undefined;
  providerSyncStatus: string | undefined;
  sourceXref: string | undefined;
  targetPlatform: string | undefined;
}

const EMPTY_FILTERS: ProfileFilters = {
  lifecycleStatus: undefined,
  controlMode: undefined,
  providerSyncStatus: undefined,
  sourceXref: undefined,
  targetPlatform: undefined,
};

export default function MachineIdentityProfilesPage() {
  const router = useRouter();
  const controls = useListControls<ProfileFilters>(EMPTY_FILTERS);
  const { filters, setFilter } = controls;
  const sourcesQuery = useDeviceSources();
  const syncSourceProfiles = useSyncSourceProfiles();
  const [discoverySource, setDiscoverySource] = useState<string>();

  const sources = useMemo(() => sourcesQuery.data ?? [], [sourcesQuery.data]);

  const profilesQuery = useCertificateProfiles({
    page: controls.page,
    size: controls.pageSize,
    search: controls.search,
    sourceXref: filters.sourceXref,
    targetPlatform: filters.targetPlatform,
    lifecycleStatus: filters.lifecycleStatus as
      ProfileLifecycleStatus | undefined,
    controlMode: filters.controlMode as ProfileControlMode | undefined,
    providerSyncStatus: filters.providerSyncStatus as
      ProfileProviderSyncStatus | undefined,
  });

  /**
   * Server-side counts of the same queries the tiles apply. Bucketing one
   * `maxPageSize` page client-side undercounted any organization with more
   * profiles than a single page and downloaded rows nothing rendered.
   */
  const scope = { sourceXref: filters.sourceXref };
  const totalCount = useCertificateProfileCount(scope);
  const activeCount = useCertificateProfileCount({
    ...scope,
    lifecycleStatus: "ACTIVE",
  });
  const draftCount = useCertificateProfileCount({
    ...scope,
    lifecycleStatus: "DRAFT",
  });
  const archivedCount = useCertificateProfileCount({
    ...scope,
    lifecycleStatus: "ARCHIVED",
  });

  const applyLifecycleTile = (status: string | undefined) => {
    setFilter(
      "lifecycleStatus",
      filters.lifecycleStatus === status ? undefined : status,
    );
  };

  const statCards: InventoryStatCard[] = [
    {
      key: "total",
      title: "Total",
      value: totalCount.data ?? 0,
      description: "All certificate profiles",
      icon: StackIcon,
      tone: "primary",
      onClick: () => setFilter("lifecycleStatus", undefined),
      isActive: filters.lifecycleStatus === undefined,
      hasError: totalCount.isError,
    },
    {
      key: "active",
      title: "Active",
      value: activeCount.data ?? 0,
      description: "Live and delivering",
      icon: CheckCircleIcon,
      tone: "success",
      onClick: () => applyLifecycleTile("ACTIVE"),
      isActive: filters.lifecycleStatus === "ACTIVE",
      hasError: activeCount.isError,
    },
    {
      key: "draft",
      title: "Draft",
      value: draftCount.data ?? 0,
      description: "Not yet dispatched",
      icon: ClipboardTextIcon,
      tone: "info",
      onClick: () => applyLifecycleTile("DRAFT"),
      isActive: filters.lifecycleStatus === "DRAFT",
      hasError: draftCount.isError,
    },
    {
      key: "archived",
      title: "Archived",
      value: archivedCount.data ?? 0,
      description: "Retired profiles",
      icon: ArchiveIcon,
      tone: "neutral",
      onClick: () => applyLifecycleTile("ARCHIVED"),
      isActive: filters.lifecycleStatus === "ARCHIVED",
      hasError: archivedCount.isError,
    },
  ];

  const { can } = usePermissions();
  const canManageProfiles = can(PERMISSIONS.iotCertificateProfileManage);
  const canSyncProfiles = can(PERMISSIONS.iotCertificateProfileSync);

  const sourceOptions = useMemo(
    () =>
      sources.map((source) => ({
        value: source.sourceXref,
        label: source.displayName,
      })),
    [sources],
  );

  const platformOptions = useMemo(() => {
    const seen = new Set<string>();
    for (const profile of profilesQuery.data?.content ?? []) {
      if (profile.targetPlatform) seen.add(profile.targetPlatform);
    }
    return Array.from(seen).map((value) => ({
      value,
      label: humanizeConstant(value),
    }));
  }, [profilesQuery.data]);

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title="Certificate profiles"
        breadcrumbs={[{ label: "Machine Identity" }]}
        subtitle="What CertPing delivers to a device source, such as an Intune Windows SCEP profile. Profiles discovered from a provider are read-only."
        actions={
          <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
            {canSyncProfiles ? (
              <>
                <Select
                  value={discoverySource}
                  onValueChange={setDiscoverySource}
                >
                  <SelectTrigger
                    className="h-8 w-full sm:w-52"
                    aria-label="Source to discover profiles from"
                  >
                    <SelectValue placeholder="Discover from source" />
                  </SelectTrigger>
                  <SelectContent>
                    {sources.length === 0 ? (
                      <p className="px-2 py-1.5 text-xs text-muted-foreground">
                        No device sources have been advertised yet.
                      </p>
                    ) : null}
                    {sources.map((source) => (
                      <SelectItem
                        key={source.sourceXref}
                        value={source.sourceXref}
                      >
                        {source.displayName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!discoverySource || syncSourceProfiles.isPending}
                  onClick={() =>
                    discoverySource &&
                    syncSourceProfiles.mutate(discoverySource)
                  }
                >
                  {syncSourceProfiles.isPending ? (
                    <CircleNotchIcon
                      className="size-4 animate-spin"
                      aria-hidden="true"
                    />
                  ) : (
                    <ArrowsClockwiseIcon
                      className="size-4"
                      aria-hidden="true"
                    />
                  )}
                  {syncSourceProfiles.isPending ? "Discovering" : "Discover"}
                </Button>
              </>
            ) : null}
            {canManageProfiles ? (
              <Button asChild size="sm">
                <Link href="/machine-identity/profiles/new">
                  <PlusIcon className="size-4" aria-hidden="true" />
                  New profile
                </Link>
              </Button>
            ) : null}
          </div>
        }
      />

      <InventoryStatCards cards={statCards} isLoading={totalCount.isLoading} />

      <PaginatedTableCard<CertificateProfileResponse>
        columns={PROFILE_COLUMNS}
        page={profilesQuery.data}
        isLoading={profilesQuery.isPending}
        isFetching={profilesQuery.isFetching}
        error={profilesQuery.error}
        errorTitle="Unable to load profiles"
        errorDescription="Certificate profiles could not be loaded."
        emptyMessage="No certificate profiles match the current filters."
        minWidthClassName="min-w-304"
        toolbar={
          <FilterBar
            searchValue={controls.searchInput}
            onSearchChange={controls.setSearchInput}
            searchPlaceholder="Search by profile name or description"
            filters={[
              {
                id: "lifecycleStatus",
                label: "Lifecycle",
                value: filters.lifecycleStatus,
                options: LIFECYCLE_OPTIONS,
                onChange: (value) => setFilter("lifecycleStatus", value),
              },
              {
                id: "sourceXref",
                label: "Source",
                value: filters.sourceXref,
                options: sourceOptions,
                onChange: (value) => setFilter("sourceXref", value),
                emptyMessage: "No device sources have been advertised yet.",
              },
              {
                id: "controlMode",
                label: "Control",
                value: filters.controlMode,
                options: CONTROL_MODE_OPTIONS,
                onChange: (value) => setFilter("controlMode", value),
              },
              {
                id: "providerSyncStatus",
                label: "Provider sync",
                value: filters.providerSyncStatus,
                options: SYNC_STATUS_OPTIONS,
                onChange: (value) => setFilter("providerSyncStatus", value),
              },
              {
                id: "targetPlatform",
                label: "Platform",
                value: filters.targetPlatform,
                options: platformOptions,
                onChange: (value) => setFilter("targetPlatform", value),
                emptyMessage: "No profile has declared a target platform yet.",
              },
            ]}
          />
        }
        onRetry={() => void profilesQuery.refetch()}
        isRetrying={profilesQuery.isFetching}
        getRowId={(profile) => profile.profileXref}
        onRowClick={(profile) =>
          router.push(`/machine-identity/profiles/${profile.profileXref}`)
        }
        onPageChange={controls.setPage}
        onPageSizeChange={controls.setPageSize}
      />
    </div>
  );
}
