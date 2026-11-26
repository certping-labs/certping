// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  WarningIcon,
  CaretDownIcon,
  ClockIcon,
  CircleNotchIcon,
  PlusIcon,
  CrosshairIcon,
  BinocularsIcon,
  MagnifyingGlassIcon,
} from "@phosphor-icons/react";

import { ProviderIcon } from "@/components/common/provider-icon";
import { Unauthorised } from "@/components/common/unautorised";
import { DiscoveryConfigsDialog } from "@/components/cert-manager/discovery/discovery-configs-dialog";
import { CertificateInventoryProgress } from "@/components/cert-manager/certificate-inventory-progress";
import {
  DISCOVERY_COLUMNS,
  DISCOVERY_HIDDEN_COLUMNS,
  DiscoveryGrid,
  ProviderCoverage,
} from "@/components/cert-manager/discovery/discovery-inventory-ui";
import { DISCOVERY_CREDENTIAL_TYPE } from "@/types/cert-manager";
import { ConnectAwsOrganizationDialog } from "@/components/cert-manager/discovery/connect-aws-organization-dialog";
import { TriggerDiscoveryDialog } from "@/components/cert-manager/discovery/trigger-discovery-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { CustomTable } from "@/components/ui/custom-table";
import { FilterSelectChip } from "@/components/ui/filter-select-chip";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { ViewSwitcher } from "@/components/ui/view-switcher";
import { useCanAddCredential, useCredentials } from "@/hooks/credentials";
import { useDiscoveryConfigs } from "@/hooks/discovery";
import { useProgressiveDiscoveredCerts } from "@/hooks/use-progressive-discovered-certs";
import { useAuth } from "@/hooks/use-auth";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import {
  canCreateCertificates,
  canDeleteDiscoveryConfigs,
  canTriggerDiscovery,
  canViewCertificates,
  canViewCredentials,
} from "@/lib/authz";
import { getApiErrorMessage } from "@/lib/backend/common";
import {
  credentialDisplayLabel,
  DISCOVERY_SOURCE_OPTIONS,
  DISCOVERY_SUPPORTED_TARGET_TYPES,
  formatDiscoveryTargetLabel,
} from "@/lib/cert-manager/discovery-display";
import { isDiscoveryCredentialEligible } from "@/lib/cert-manager/discovery-credential-policy";
import {
  discoveryConfigStatusLabel,
  discoveryConfigStatusMessage,
  discoveryConfigStatusVariant,
  isActiveDiscoveryConfigStatus,
  isFailedDiscoveryConfigStatus,
} from "@/lib/cert-manager/discovery-status";
import { resolveCredentialProviderFromApiValue } from "@/lib/credential-providers";
import type { DiscoveryFilters, DiscoveryRunResponse } from "@/types/discovery";
import { cn, formatDateTimeCompact } from "@/lib/utils";

const SEARCH_DEBOUNCE_MS = 350;

const CREDENTIALS_PERMISSION_REQUIRED =
  "You need permission to view credentials to start a scan. Ask an admin.";

const CERT_STATUS_OPTIONS = [
  { value: "ISSUED", label: "Issued" },
  { value: "EXPIRED", label: "Expired" },
  { value: "INACTIVE", label: "Inactive" },
  { value: "REVOKED", label: "Revoked" },
  { value: "PENDING_VALIDATION", label: "Pending validation" },
] as const;

const EXPIRES_WITHIN_OPTIONS = [
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "60", label: "60 days" },
  { value: "90", label: "90 days" },
] as const;

const SOURCE_CHIP_OPTIONS = [
  { value: "all", label: "All sources" },
  ...DISCOVERY_SOURCE_OPTIONS,
];
const STATUS_CHIP_OPTIONS = [
  { value: "all", label: "All statuses" },
  ...CERT_STATUS_OPTIONS,
];
const EXPIRY_CHIP_OPTIONS = [
  { value: "all", label: "Any expiry" },
  ...EXPIRES_WITHIN_OPTIONS.map((option) => ({
    value: option.value,
    label: `Within ${option.label}`,
  })),
];
const MANAGED_CHIP_OPTIONS = [
  { value: "all", label: "Managed and external" },
  { value: "managed", label: "Managed by CertPing" },
  { value: "external", label: "Not managed by CertPing" },
];

const EMPTY_DISCOVERY_FILTERS: DiscoveryFilters = {};

function shouldShowScanStatus(config: DiscoveryRunResponse): boolean {
  return (
    isActiveDiscoveryConfigStatus(config.status) ||
    isFailedDiscoveryConfigStatus(config.status) ||
    config.status === "PARTIAL" ||
    config.status === "CANCELLED"
  );
}

function DiscoveryScanStatusRail({
  configs,
  credentialLabelByXref,
  onManage,
}: {
  configs: DiscoveryRunResponse[];
  credentialLabelByXref: Map<string, string>;
  /** Absent when the user can neither run nor remove saved scans. */
  onManage?: () => void;
}) {
  const [isExpanded, setIsExpanded] = React.useState(false);

  if (configs.length === 0) return null;

  const failedCount = configs.filter((config) =>
    isFailedDiscoveryConfigStatus(config.status),
  ).length;
  const cancelledCount = configs.filter(
    (config) => config.status === "CANCELLED",
  ).length;
  const partialCount = configs.filter(
    (config) => config.status === "PARTIAL",
  ).length;
  const activeConfigs = configs.filter((config) =>
    isActiveDiscoveryConfigStatus(config.status),
  );
  const collapsedConfigs = configs.filter(
    (config) => !isActiveDiscoveryConfigStatus(config.status),
  );

  const renderStatusRow = (config: DiscoveryRunResponse) => {
    const credentialLabel =
      (config.credentialXref &&
        credentialLabelByXref.get(config.credentialXref)) ||
      config.credentialXref ||
      "Saved credential";
    const lastEventAt = config.completedAt ?? config.startedAt;
    const variant = discoveryConfigStatusVariant(config.status);
    const message = discoveryConfigStatusMessage(config);

    return (
      <div
        key={config.configId ?? `${config.targetType}-${config.requestId}`}
        className="grid gap-2 py-2 md:grid-cols-[minmax(11rem,16rem)_minmax(0,1fr)_auto]"
      >
        <div className="flex min-w-0 items-center gap-2">
          <span className="flex size-8 shrink-0 items-center justify-center rounded border bg-background">
            <ProviderIcon
              provider={
                resolveCredentialProviderFromApiValue(config.targetType) ??
                "aws"
              }
              serviceApiValue={config.targetType}
              size={18}
            />
          </span>
          <div className="min-w-0">
            <div className="truncate text-sm font-medium text-foreground">
              {formatDiscoveryTargetLabel(config.targetType)}
            </div>
            <div className="truncate font-mono text-xs text-muted-foreground">
              {credentialLabel}
            </div>
          </div>
        </div>

        <p
          className={cn(
            "min-w-0 truncate text-sm",
            variant === "destructive"
              ? "text-destructive"
              : "text-muted-foreground",
          )}
          title={message}
        >
          {message}
        </p>

        <div className="flex items-center gap-2 md:justify-end">
          <Badge variant={variant}>
            {discoveryConfigStatusLabel(config.status)}
          </Badge>
          {lastEventAt ? (
            <span className="inline-flex items-center gap-1 text-xs whitespace-nowrap text-muted-foreground">
              <ClockIcon className="h-3.5 w-3.5" aria-hidden="true" />
              {formatDateTimeCompact(lastEventAt)}
            </span>
          ) : null}
        </div>
      </div>
    );
  };

  return (
    <Collapsible
      open={isExpanded}
      onOpenChange={setIsExpanded}
      className="rounded-md border border-border bg-card px-3 py-2"
      role="status"
      aria-live="polite"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={cn(
              "flex size-7 shrink-0 items-center justify-center rounded-md border",
              failedCount > 0
                ? "border-danger-border bg-danger-soft text-destructive"
                : "border-warning-100 bg-warning-50 text-warning",
            )}
          >
            {activeConfigs.length > 0 ? (
              <CircleNotchIcon className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <WarningIcon className="h-3.5 w-3.5" />
            )}
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold text-foreground">
                Discovery scan status
              </h2>
              {failedCount > 0 ? (
                <Badge variant="destructive">{failedCount} failed</Badge>
              ) : null}
              {activeConfigs.length > 0 ? (
                <Badge variant="warning">{activeConfigs.length} running</Badge>
              ) : null}
              {partialCount > 0 ? (
                <Badge variant="warning">{partialCount} partial</Badge>
              ) : null}
              {cancelledCount > 0 ? (
                <Badge variant="secondary">{cancelledCount} cancelled</Badge>
              ) : null}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1">
          {onManage ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onManage}
            >
              Manage
            </Button>
          ) : null}
          {collapsedConfigs.length > 0 ? (
            <CollapsibleTrigger asChild>
              <Button type="button" variant="ghost" size="sm">
                {isExpanded ? "Hide" : "Show"} {collapsedConfigs.length}
                <CaretDownIcon
                  className={cn(
                    "h-4 w-4 transition-transform",
                    isExpanded && "rotate-180",
                  )}
                  aria-hidden="true"
                />
              </Button>
            </CollapsibleTrigger>
          ) : null}
        </div>
      </div>

      {activeConfigs.length > 0 ? (
        <div className="mt-2 divide-y divide-border">
          {activeConfigs.map(renderStatusRow)}
        </div>
      ) : null}

      {collapsedConfigs.length > 0 ? (
        <CollapsibleContent>
          <div className="mt-2 divide-y divide-border border-t">
            {collapsedConfigs.map(renderStatusRow)}
          </div>
        </CollapsibleContent>
      ) : null}
    </Collapsible>
  );
}

function normalizeFilters(
  update: Partial<DiscoveryFilters>,
  base: DiscoveryFilters,
): DiscoveryFilters {
  const next: DiscoveryFilters = { ...base, ...update };

  (Object.keys(next) as (keyof DiscoveryFilters)[]).forEach((key) => {
    const value = next[key];
    if (value === "" || value === undefined) {
      delete next[key];
    }
  });

  return next;
}

function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debouncedValue, setDebouncedValue] = React.useState(value);

  React.useEffect(() => {
    const handle = window.setTimeout(() => setDebouncedValue(value), delayMs);
    return () => window.clearTimeout(handle);
  }, [delayMs, value]);

  return debouncedValue;
}

function DiscoveryTableSkeleton() {
  return (
    <div className="space-y-2" role="status" aria-label="Loading certificates">
      {Array.from({ length: 8 }).map((_, index) => (
        <Skeleton key={index} className="h-12 w-full rounded-md" />
      ))}
    </div>
  );
}

function DiscoveryPageSkeleton() {
  return (
    <div className="space-y-6 p-6" role="status" aria-label="Loading page">
      <Skeleton className="h-24 rounded-md" />
      <Skeleton className="h-32 rounded-md" />
      <Skeleton className="h-64 rounded-md" />
    </div>
  );
}

export default function DiscoveryPage() {
  const router = useRouter();
  const { user, isLoading: isLoadingAuth } = useAuth();

  const canView = canViewCertificates(user);
  const canTrigger = canTriggerDiscovery(user);
  const canDeleteConfigs = canDeleteDiscoveryConfigs(user);
  const canManageConfigs = canTrigger || canDeleteConfigs;
  const isCertIssuanceEnabled = useIsFeatureEnabled("CERTIFICATE_ISSUANCE");
  const canIssue = canCreateCertificates(user) && isCertIssuanceEnabled;
  const canViewCreds = canViewCredentials(user);
  const canAddDeploymentCredential = useCanAddCredential("DEPLOYMENT");

  const [triggerOpen, setTriggerOpen] = useState(false);
  const [configsOpen, setConfigsOpen] = useState(false);
  const [awsOrgOpen, setAwsOrgOpen] = useState(false);
  const [filters, setFilters] = useState<DiscoveryFilters>({});
  const [domainInput, setDomainInput] = useState("");
  const [viewMode, setViewMode] = useResponsiveViewMode({
    storageKey: "discovery_view",
  });

  const debouncedDomain = useDebouncedValue(domainInput, SEARCH_DEBOUNCE_MS);
  const certificatesQuery = useProgressiveDiscoveredCerts(filters, {
    enabled: canView,
  });
  const hasActiveFilters = Object.keys(filters).length > 0;
  const metricCertificatesQuery = useProgressiveDiscoveredCerts(
    EMPTY_DISCOVERY_FILTERS,
    {
      // Avoid two full inventory scans competing for database capacity.
      enabled:
        canView && hasActiveFilters && certificatesQuery.isInventoryComplete,
    },
  );
  const { data, isLoading, error: certsError, refetch } = certificatesQuery;
  const { data: discoveryConfigs, refetch: refetchConfigs } =
    useDiscoveryConfigs({ enabled: canView });
  const credentialsQuery = useCredentials({ enabled: canViewCreds });

  const activeConfig = useMemo<DiscoveryRunResponse | null>(
    () =>
      (discoveryConfigs ?? []).find((config) =>
        isActiveDiscoveryConfigStatus(config.status),
      ) ?? null,
    [discoveryConfigs],
  );

  const deploymentCredentials = useMemo(
    () =>
      credentialsQuery.data?.filter(
        (credential) =>
          (credential.type === "DEPLOYMENT" ||
            String(credential.type) === DISCOVERY_CREDENTIAL_TYPE) &&
          DISCOVERY_SUPPORTED_TARGET_TYPES.has(
            credential.targetType ??
              credential.providerName ??
              credential.provider ??
              "",
          ),
      ) ?? [],
    [credentialsQuery.data],
  );

  const discoveryEligibleCredentials = useMemo(
    () =>
      deploymentCredentials.filter((credential) =>
        isDiscoveryCredentialEligible(credential),
      ),
    [deploymentCredentials],
  );

  const hasUnsupportedDiscoveryCredentials =
    deploymentCredentials.length > 0 &&
    discoveryEligibleCredentials.length === 0;

  const credentialLabelByXref = useMemo(() => {
    const map = new Map<string, string>();
    for (const credential of credentialsQuery.data ?? []) {
      if (credential.credentialXref) {
        map.set(credential.credentialXref, credentialDisplayLabel(credential));
      }
    }
    return map;
  }, [credentialsQuery.data]);

  const applyFilter = useCallback((update: Partial<DiscoveryFilters>) => {
    setFilters((previousFilters) => normalizeFilters(update, previousFilters));
  }, []);

  const clearAllFilters = useCallback(() => {
    setFilters({});
    setDomainInput("");
  }, []);

  const handleDomainCommit = useCallback(() => {
    applyFilter({ domain: domainInput.trim() || undefined });
  }, [applyFilter, domainInput]);

  const handleScanDispatched = useCallback(
    (info: {
      targetType: string;
      credentialLabel: string;
      result: DiscoveryRunResponse;
    }) => {
      void refetchConfigs();

      if (DISCOVERY_SUPPORTED_TARGET_TYPES.has(info.targetType)) {
        applyFilter({ targetType: info.targetType });
      }
    },
    [applyFilter, refetchConfigs],
  );

  React.useEffect(() => {
    applyFilter({ domain: debouncedDomain.trim() || undefined });
  }, [applyFilter, debouncedDomain]);

  const previousActiveConfigId = React.useRef<number | null>(null);
  React.useEffect(() => {
    const currentId = activeConfig?.configId ?? null;
    const previousId = previousActiveConfigId.current;
    if (previousId !== null && currentId !== previousId) {
      void refetch();
    }
    previousActiveConfigId.current = currentId;
  }, [activeConfig?.configId, refetch]);

  if (isLoadingAuth) {
    return <DiscoveryPageSkeleton />;
  }

  if (!canView) {
    return (
      <div className="p-6">
        <Unauthorised />
      </div>
    );
  }

  const certificates = data ?? [];
  const metricCertificates = hasActiveFilters
    ? (metricCertificatesQuery.data ?? [])
    : certificates;
  const isLoadingMetrics = hasActiveFilters
    ? metricCertificatesQuery.isLoading
    : isLoading;
  const visibleScanStatusConfigs = (discoveryConfigs ?? []).filter(
    shouldShowScanStatus,
  );
  const headerActionVariant =
    !isLoadingMetrics &&
    metricCertificates.some((cert) => cert.managed === false)
      ? "outline"
      : "default";

  return (
    <>
      <div className="space-y-6 p-6">
        <section className="space-y-4">
          <PageHeader
            title="Discovery"
            subtitle="Certificate inventory from AWS (one account or a whole organization), Azure Key Vault, and Kubernetes Secrets."
            actions={
              canManageConfigs ? (
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setConfigsOpen(true)}
                  >
                    Manage scan configs
                  </Button>
                  {canTrigger && canAddDeploymentCredential ? (
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setAwsOrgOpen(true)}
                    >
                      Connect AWS
                    </Button>
                  ) : null}
                  {canTrigger ? (
                    // Without credential:read the credentials query never
                    // runs, so the list is empty rather than loading; say why
                    // instead of offering to add a credential or claiming
                    // none exist.
                    !canViewCreds ? (
                      <Button
                        disabled
                        variant={headerActionVariant}
                        title={CREDENTIALS_PERMISSION_REQUIRED}
                      >
                        <CrosshairIcon className="h-4 w-4" aria-hidden="true" />
                        Trigger scan
                      </Button>
                    ) : credentialsQuery.isLoading ? (
                      <Button
                        disabled
                        title="Loading credentials"
                        isPending={credentialsQuery.isLoading}
                      >
                        Loading
                      </Button>
                    ) : deploymentCredentials.length === 0 &&
                      canAddDeploymentCredential ? (
                      <Button asChild variant={headerActionVariant}>
                        <Link href="/integrations/connections/add?type=DEPLOYMENT">
                          <PlusIcon className="h-4 w-4" aria-hidden="true" />
                          Add deployment target
                        </Link>
                      </Button>
                    ) : discoveryEligibleCredentials.length === 0 ? (
                      <Button
                        disabled
                        variant={headerActionVariant}
                        title="No credentials are configured for discovery"
                      >
                        <CrosshairIcon className="h-4 w-4" aria-hidden="true" />
                        Trigger scan
                      </Button>
                    ) : (
                      <Button
                        variant={headerActionVariant}
                        onClick={() => setTriggerOpen(true)}
                      >
                        <CrosshairIcon className="h-4 w-4" aria-hidden="true" />
                        Trigger scan
                      </Button>
                    )
                  ) : null}
                </div>
              ) : null
            }
          />

          <div className="space-y-3">
            <ProviderCoverage
              certificates={metricCertificates}
              isLoading={isLoadingMetrics}
              selectedTargetType={filters.targetType}
              onSelectTargetType={(targetType) => applyFilter({ targetType })}
              onFocusUnmanaged={() => applyFilter({ managed: false })}
              onFocusExpiring={() => applyFilter({ expiresWithinDays: 30 })}
              onFocusUnmanagedExpiring={() =>
                applyFilter({ managed: false, expiresWithinDays: 30 })
              }
              canIssue={canIssue}
            />
          </div>

          <DiscoveryScanStatusRail
            configs={visibleScanStatusConfigs}
            credentialLabelByXref={credentialLabelByXref}
            onManage={canManageConfigs ? () => setConfigsOpen(true) : undefined}
          />

          {hasUnsupportedDiscoveryCredentials ? (
            <Alert className="bg-card">
              <WarningIcon className="h-4 w-4" />
              <AlertTitle>No credentials are ready for discovery</AlertTitle>
              <AlertDescription>
                You have supported deployment targets, but none can be used for
                discovery in this environment. Secret-backed credentials need a
                Key Vault path; ambient auth modes are only supported where the
                backend agent can use them.
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-full sm:w-72">
              <MagnifyingGlassIcon
                className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
                aria-hidden
              />
              <Input
                value={domainInput}
                onChange={(event) => setDomainInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") handleDomainCommit();
                }}
                onBlur={handleDomainCommit}
                placeholder="Search by domain"
                className="h-9 pl-9"
                aria-label="Search certificates by domain"
              />
            </div>
            <FilterSelectChip
              label="Source"
              value={filters.targetType ?? "all"}
              options={SOURCE_CHIP_OPTIONS}
              onValueChange={(value) =>
                applyFilter({ targetType: value === "all" ? undefined : value })
              }
            />
            <FilterSelectChip
              label="Status"
              value={filters.certStatus ?? "all"}
              options={STATUS_CHIP_OPTIONS}
              onValueChange={(value) =>
                applyFilter({ certStatus: value === "all" ? undefined : value })
              }
            />
            <FilterSelectChip
              label="Expiry"
              value={
                filters.expiresWithinDays !== undefined
                  ? String(filters.expiresWithinDays)
                  : "all"
              }
              options={EXPIRY_CHIP_OPTIONS}
              onValueChange={(value) =>
                applyFilter({
                  expiresWithinDays:
                    value === "all" ? undefined : Number(value),
                })
              }
            />
            <FilterSelectChip
              label="Managed"
              value={
                filters.managed === undefined
                  ? "all"
                  : filters.managed
                    ? "managed"
                    : "external"
              }
              options={MANAGED_CHIP_OPTIONS}
              onValueChange={(value) =>
                applyFilter({
                  managed: value === "all" ? undefined : value === "managed",
                })
              }
            />
            {hasActiveFilters ? (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-8 text-muted-foreground"
                onClick={clearAllFilters}
              >
                Clear filters
              </Button>
            ) : null}
            <div className="ml-auto">
              <ViewSwitcher
                size="sm"
                value={viewMode}
                onValueChange={setViewMode}
              />
            </div>
          </div>
        </section>

        <CertificateInventoryProgress
          isLoading={certificatesQuery.isLoadingAdditionalPages}
          hasError={certificatesQuery.isFetchNextPageError}
          loadedItems={certificatesQuery.loadedItems}
          totalItems={certificatesQuery.totalItems}
          onRetry={() => {
            void certificatesQuery.retryAdditionalPages();
          }}
        />

        {hasActiveFilters ? (
          <CertificateInventoryProgress
            isLoading={metricCertificatesQuery.isLoadingAdditionalPages}
            hasError={metricCertificatesQuery.isFetchNextPageError}
            loadedItems={metricCertificatesQuery.loadedItems}
            totalItems={metricCertificatesQuery.totalItems}
            inventoryLabel="discovery summary"
            itemLabel="certificates"
            onRetry={() => {
              void metricCertificatesQuery.retryAdditionalPages();
            }}
          />
        ) : null}

        {isLoading ? (
          <DiscoveryTableSkeleton />
        ) : certsError && certificates.length === 0 ? (
          <Alert variant="destructive" className="bg-card">
            <WarningIcon className="h-4 w-4" />
            <AlertTitle>Failed to load certificates</AlertTitle>
            <AlertDescription>
              {getApiErrorMessage(
                certsError,
                "An unexpected error occurred. Please try again.",
              )}
            </AlertDescription>
          </Alert>
        ) : certificates.length === 0 ? (
          <Alert className="bg-card">
            <BinocularsIcon className="h-4 w-4" />
            <AlertTitle>
              {hasActiveFilters
                ? "No certificates match the current filters"
                : "No discovered certificates yet"}
            </AlertTitle>
            <AlertDescription>
              {hasActiveFilters
                ? "Adjust the filters above to widen the results."
                : canTrigger
                  ? "Trigger a scan to discover certificates from your cloud and Kubernetes targets."
                  : "Certificates appear here after a discovery scan runs."}
            </AlertDescription>
          </Alert>
        ) : (
          <div data-discovery-table>
            <CustomTable
              columns={DISCOVERY_COLUMNS}
              data={certificates}
              getRowId={(row) => String(row.id)}
              showColumnVisibility={false}
              defaultHiddenColumns={DISCOVERY_HIDDEN_COLUMNS}
              showPagination
              manualFiltering
              onRowClick={(row) =>
                router.push(`/cert-manager/discovery/${row.id}`)
              }
              viewMode={viewMode === "card" ? "grid" : "table"}
              renderGrid={(rows) => (
                <DiscoveryGrid
                  certificates={rows}
                  onSelect={(id) =>
                    router.push(`/cert-manager/discovery/${id}`)
                  }
                />
              )}
            />
          </div>
        )}
      </div>

      {canTrigger ? (
        <TriggerDiscoveryDialog
          open={triggerOpen}
          onOpenChange={setTriggerOpen}
          credentials={discoveryEligibleCredentials}
          onScanDispatched={handleScanDispatched}
        />
      ) : null}

      {canTrigger && canAddDeploymentCredential ? (
        <ConnectAwsOrganizationDialog
          open={awsOrgOpen}
          onOpenChange={setAwsOrgOpen}
        />
      ) : null}

      {canManageConfigs ? (
        <DiscoveryConfigsDialog
          open={configsOpen}
          onOpenChange={setConfigsOpen}
          canManage={canTrigger}
          canDelete={canDeleteConfigs}
        />
      ) : null}
    </>
  );
}
