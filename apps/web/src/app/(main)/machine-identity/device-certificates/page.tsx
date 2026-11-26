// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  CalendarXIcon,
  CheckCircleIcon,
  ClockIcon,
  StackIcon,
} from "@phosphor-icons/react";

import {
  CERTIFICATE_COLUMNS,
  CERTIFICATE_DEFAULT_HIDDEN_COLUMNS,
} from "@/components/machine-identity/certificate-columns";
import { FilterBar } from "@/components/machine-identity/filter-bar";
import {
  InventoryStatCards,
  type InventoryStatCard,
} from "@/components/machine-identity/inventory-stat-cards";
import { PaginatedTableCard } from "@/components/machine-identity/paginated-table-card";
import { PageHeader } from "@/components/ui/page-header";
import { useCaConnectors } from "@/hooks/machine-identity/use-ca-connectors";
import { useCertificateProfiles } from "@/hooks/machine-identity/use-certificate-profiles";
import { useDeviceSources } from "@/hooks/machine-identity/use-device-sources";
import {
  useCertificateCount,
  useCertificates,
} from "@/hooks/machine-identity/use-machine-certificates";
import { useListControls } from "@/hooks/machine-identity/use-list-controls";
import {
  caProviderLabel,
  CERTIFICATE_RENEWAL_STATE_LABELS,
} from "@/lib/machine-identity/backend-display";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import type {
  CertificateRenewalState,
  CertificateStatusFilter,
} from "@/types/machine-identity-backend";

const CERTIFICATE_STATUSES = ["ISSUED", "EXPIRING", "EXPIRED"] as const;

/**
 * Expiry is one control, not two.
 *
 * <p>The API accepts `status` and `expiringWithinDays` separately but silently
 * lets `status` win when both arrive, so a UI offering both could show
 * "Expired + within 7 days" while returning only expired certificates. Folding
 * them into a single filter makes that contradiction unrepresentable.
 */
const EXPIRY_OPTIONS = [
  { value: "ISSUED", label: "Issued (over 30 days left)" },
  { value: "EXPIRING", label: "Expiring (within 30 days)" },
  { value: "EXPIRED", label: "Expired" },
  { value: "7", label: "Expiring within 7 days" },
  { value: "14", label: "Expiring within 14 days" },
  { value: "90", label: "Expiring within 90 days" },
] as const;

function isStatusValue(
  value: string | undefined,
): value is CertificateStatusFilter {
  return CERTIFICATE_STATUSES.includes(value as CertificateStatusFilter);
}

function isRenewalState(
  value: string | undefined,
): value is CertificateRenewalState {
  return value === "NONE" || value === "NUDGING" || value === "RENEWED";
}

/** The operator-driven renewal states worth filtering on; `NONE` is the resting default. */
const RENEWAL_STATE_OPTIONS = (["NUDGING", "RENEWED"] as const).map(
  (state) => ({
    value: state,
    label: CERTIFICATE_RENEWAL_STATE_LABELS[state],
  }),
);

interface CertificateFilters extends Record<string, string | undefined> {
  /** Either a `CertificateStatusFilter` or a day window; never both. */
  expiry: string | undefined;
  renewalState: string | undefined;
  caProvider: string | undefined;
  profileXref: string | undefined;
  sourceXref: string | undefined;
}

const EMPTY_FILTERS: CertificateFilters = {
  expiry: undefined,
  renewalState: undefined,
  caProvider: undefined,
  profileXref: undefined,
  sourceXref: undefined,
};

export default function MachineIdentityCertificatesPage() {
  const router = useRouter();
  const controls = useListControls<CertificateFilters>(EMPTY_FILTERS);
  const { filters, setFilter } = controls;

  const caConnectorsQuery = useCaConnectors();
  const sourcesQuery = useDeviceSources();
  // Large page so the filter dropdown covers every profile, not just the first.
  const profilesQuery = useCertificateProfiles({
    size: MACHINE_IDENTITY_CONFIG.list.maxPageSize,
  });

  const caProviderOptions = useMemo(() => {
    const seen = new Set<string>();
    for (const connector of caConnectorsQuery.data ?? []) {
      seen.add(connector.caProvider);
    }
    return Array.from(seen).map((value) => ({
      value,
      label: caProviderLabel(value),
    }));
  }, [caConnectorsQuery.data]);

  const profileOptions = useMemo(
    () =>
      (profilesQuery.data?.content ?? []).map((profile) => ({
        value: profile.profileXref,
        label: profile.name,
      })),
    [profilesQuery.data],
  );

  const sourceOptions = useMemo(
    () =>
      (sourcesQuery.data ?? []).map((source) => ({
        value: source.sourceXref,
        label: source.displayName,
      })),
    [sourcesQuery.data],
  );

  const expiry = filters.expiry;
  const scopeFilters = {
    caProvider: filters.caProvider,
    profileXref: filters.profileXref,
    sourceXref: filters.sourceXref,
    renewalState: isRenewalState(filters.renewalState)
      ? filters.renewalState
      : undefined,
  };

  const certificatesQuery = useCertificates({
    page: controls.page,
    size: controls.pageSize,
    search: controls.search,
    ...scopeFilters,
    status: isStatusValue(expiry) ? expiry : undefined,
    expiringWithinDays:
      expiry && !isStatusValue(expiry) ? Number(expiry) : undefined,
    renewalState: filters.renewalState as CertificateRenewalState | undefined,
  });

  /**
   * Each tile is a server-side count of the same query the tile applies, so a
   * tile and the table it filters can never disagree. The counts respect the
   * CA/profile/source filters already in force - a tile that ignored them
   * would describe a different population than the one on screen.
   */
  const totalCount = useCertificateCount(scopeFilters);
  const issuedCount = useCertificateCount({
    ...scopeFilters,
    status: "ISSUED",
  });
  const expiringCount = useCertificateCount({
    ...scopeFilters,
    status: "EXPIRING",
  });
  const expiredCount = useCertificateCount({
    ...scopeFilters,
    status: "EXPIRED",
  });

  const applyExpiryTile = (value: string | undefined) => {
    setFilter("expiry", filters.expiry === value ? undefined : value);
  };

  const statCards: InventoryStatCard[] = [
    {
      key: "total",
      title: "Total",
      value: totalCount.data ?? 0,
      description: "All device certificates",
      icon: StackIcon,
      tone: "primary",
      onClick: () => setFilter("expiry", undefined),
      isActive: expiry === undefined,
      hasError: totalCount.isError,
    },
    {
      key: "issued",
      title: "Issued",
      value: issuedCount.data ?? 0,
      description: "Over 30 days left",
      icon: CheckCircleIcon,
      tone: "success",
      onClick: () => applyExpiryTile("ISSUED"),
      isActive: expiry === "ISSUED",
      hasError: issuedCount.isError,
    },
    {
      key: "expiring",
      title: "Expiring",
      value: expiringCount.data ?? 0,
      description: "Within 30 days",
      icon: ClockIcon,
      tone: (expiringCount.data ?? 0) > 0 ? "warning" : "neutral",
      onClick: () => applyExpiryTile("EXPIRING"),
      isActive: expiry === "EXPIRING",
      hasError: expiringCount.isError,
    },
    {
      key: "expired",
      title: "Expired",
      value: expiredCount.data ?? 0,
      description: "Past validity",
      icon: CalendarXIcon,
      tone: (expiredCount.data ?? 0) > 0 ? "danger" : "neutral",
      onClick: () => applyExpiryTile("EXPIRED"),
      isActive: expiry === "EXPIRED",
      hasError: expiredCount.isError,
    },
  ];

  const shownCertificates = certificatesQuery.data?.totalElements;

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title="Device certificates"
        breadcrumbs={[{ label: "Machine Identity" }]}
        subtitle="Every certificate issued to a device across your connected CAs, soonest expiry first."
        badge={
          shownCertificates === undefined
            ? undefined
            : {
                label: `${shownCertificates.toLocaleString()} shown`,
                variant: "secondary",
              }
        }
      />

      <InventoryStatCards cards={statCards} isLoading={totalCount.isLoading} />

      <PaginatedTableCard
        columns={CERTIFICATE_COLUMNS}
        page={certificatesQuery.data}
        isLoading={certificatesQuery.isPending}
        isFetching={certificatesQuery.isFetching}
        error={certificatesQuery.error}
        errorTitle="Unable to load certificates"
        errorDescription="The certificate inventory could not be loaded."
        emptyMessage="No certificates match the current filters."
        // Floor matches the width of the columns shown by default. The three
        // hidden ones are the ones a row rarely needs: the issuer DN restates
        // the CA, and both dates are summarised by "Remaining". Each is one
        // click away in the Columns menu.
        minWidthClassName="min-w-304"
        defaultHiddenColumns={CERTIFICATE_DEFAULT_HIDDEN_COLUMNS}
        toolbar={
          <FilterBar
            searchValue={controls.searchInput}
            onSearchChange={controls.setSearchInput}
            searchPlaceholder="Search by common name, serial, or device"
            filters={[
              {
                id: "expiry",
                label: "Expiry",
                value: filters.expiry,
                options: EXPIRY_OPTIONS,
                onChange: (value) => setFilter("expiry", value),
              },
              {
                id: "renewalState",
                label: "Renewal",
                value: filters.renewalState,
                options: RENEWAL_STATE_OPTIONS,
                onChange: (value) => setFilter("renewalState", value),
              },
              {
                id: "caProvider",
                label: "CA",
                value: filters.caProvider,
                options: caProviderOptions,
                onChange: (value) => setFilter("caProvider", value),
                emptyMessage: "No CA connector has reported in yet.",
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
                id: "profileXref",
                label: "Profile",
                value: filters.profileXref,
                options: profileOptions,
                onChange: (value) => setFilter("profileXref", value),
                emptyMessage: "No certificate profiles exist yet.",
              },
              {
                id: "renewalState",
                label: "Renewal",
                value: filters.renewalState,
                options: RENEWAL_STATE_OPTIONS,
                onChange: (value) => setFilter("renewalState", value),
              },
            ]}
          />
        }
        onRetry={() => void certificatesQuery.refetch()}
        isRetrying={certificatesQuery.isFetching}
        getRowId={(certificate) => certificate.certificateXref}
        onRowClick={(certificate) =>
          router.push(
            `/machine-identity/device-certificates/${certificate.certificateXref}`,
          )
        }
        onPageChange={controls.setPage}
        onPageSizeChange={controls.setPageSize}
      />
    </div>
  );
}
