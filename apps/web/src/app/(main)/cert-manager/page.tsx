// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  WarningIcon,
  XCircleIcon,
  CheckCircleIcon,
  CaretLeftIcon,
  CaretRightIcon,
  ClockIcon,
  CircleNotchIcon,
  PlusIcon,
  ShieldIcon,
  TrashIcon,
  InfoIcon,
} from "@phosphor-icons/react";

import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { useAuth } from "@/hooks/use-auth";
import { useIsMobile } from "@/hooks/use-mobile";
import { useCanDownloadCertificates } from "@/hooks/certificate-download-access";
import {
  useDeletePendingSSLCertificate,
  useGetTxtRecords,
  useRenewCertificate,
  useRevokeCertificate,
  useCompleteDnsChallenge,
} from "@/hooks/ssl";
import { useAnimatedCount } from "@/hooks/use-animated-count";
import { useBulkDeleteCertificates } from "@/hooks/use-bulk-delete-certificates";
import { useInventoryRowSelection } from "@/hooks/use-inventory-row-selection";
import { useCertificateTableUrlFilters } from "@/hooks/use-certificate-table-url-filters";
import { useProgressiveCertificateList } from "@/hooks/use-progressive-certificate-list";
import {
  canCreateCertificates,
  canCreateDeployments,
  canExportPrivateKey,
  canDeleteCertificates,
  canRenewCertificates,
  canRevokeCertificates,
  canUpdateCredentials,
  canViewCertificates,
  canViewDeployments,
} from "@/lib/authz";
import { getCertificateManagementLabel } from "@/lib/certificate-management";
import { getProviderPresentation } from "@/lib/credential-providers";
import { compareDateValues } from "@/lib/table-sorting";
import { errorReference } from "@/lib/correlation-id";
import { cn, formatDate, getExpiryLabel, getRemainingDays } from "@/lib/utils";
import { Unauthorised } from "@/components/common/unautorised";
import { SomethingWentWrong } from "@/components/common/error";
import { MetricCard, MetricStrip } from "@/components/common/metric-card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import { type ColumnFilter, CustomTable } from "@/components/ui/custom-table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ViewMode, ViewSwitcher } from "@/components/ui/view-switcher";
import type { SSLCertificateListItem } from "@/types/ssl";
import { CertificateManagementDialog } from "@/components/cert-manager/certificate-management-dialog";
import { CertificateInventoryProgress } from "@/components/cert-manager/certificate-inventory-progress";
import {
  ManualTxtRecordsDialog,
  type ManualTxtRecordsDialogState,
} from "@/components/cert-manager/manual-txt-records-dialog";
import { PageHeader } from "@/components/ui/page-header";
import { LazyDownloadCertificateDialog } from "@/components/cert-manager/certificate-download/lazy-download-certificate-dialog";
import { BulkDeleteCertificatesDialog } from "@/components/cert-manager/bulk-delete-certificates-dialog";
import { CertificateActions } from "@/components/cert-manager/certificate-row-actions";
import type { CertificateDownloadTarget } from "@/types/certificate-export";
import { ToolTipCard } from "@/components/common/tooltip-card";
import {
  canDeleteCertificateRecord,
  canViewCertificateDetails,
  formatCertificateStatusLabel,
  getCertificateDetailHref,
  getCertificateRenewalBucket,
  getCertificateStatusBadgeVariant,
  getCoverageSummary,
  getManagementSummary,
} from "@/lib/cert-manager/certificates-page-helpers";
import {
  computeCertificateDashboardMetrics,
  filterCertificatesForCardView,
  getCertificateIssuerOptions,
  getCertificateProviderOptions,
  sortCertificatesByAttention,
} from "@/lib/cert-manager/certificate-dashboard-helpers";
import {
  CERTIFICATE_STATUS_FILTER_OPTIONS,
  isEndedCertificateStatus,
  isFailedCertificateStatus,
  isInFlightCertificateStatus,
  isNeedsActionCertificateStatus,
  isServingCertificateStatus,
  normalizeCertificateStatus,
} from "@/lib/cert-manager/certificate-status";
import {
  collectDeletableDomainIds,
  pickDeletableFailedCertificates,
} from "@/lib/cert-manager/bulk-certificate-delete";
import {
  readCertificateViewPreference,
  writeCertificateViewPreference,
} from "@/lib/cert-manager/certificate-view-preference";

const CARD_PAGE_SIZE = 6;

function CertificateStatusIcon({
  status,
}: {
  status: SSLCertificateListItem["status"];
}) {
  if (isInFlightCertificateStatus(status)) {
    return (
      <CircleNotchIcon className="h-4 w-4 animate-spin text-[hsl(var(--warning-700))]" />
    );
  }
  if (
    isNeedsActionCertificateStatus(status) ||
    normalizeCertificateStatus(status) === "REVOCATION_FAILED"
  ) {
    return <WarningIcon className="h-4 w-4 text-[hsl(var(--warning-700))]" />;
  }
  if (isServingCertificateStatus(status)) {
    return <CheckCircleIcon className="h-4 w-4 text-[hsl(var(--success))]" />;
  }
  if (isFailedCertificateStatus(status) || isEndedCertificateStatus(status)) {
    return <XCircleIcon className="h-4 w-4 text-[hsl(var(--danger))]" />;
  }
  return null;
}

type PendingAction = {
  type: "revoke" | "delete";
  certificate: SSLCertificateListItem;
} | null;

/**
 * Filters by expiry date alone, so it stays whether or not CERTIFICATE_RENEWAL
 * is on: knowing what expires soon matters most when CertPing isn't renewing.
 */
const EXPIRY_FILTER: ColumnFilter = {
  id: "renewalWindow",
  type: "select",
  label: "Expiry",
  placeholder: "Expiry",
  options: [
    { label: "All expiry dates", value: "all" },
    { label: "Expiring in 30 days", value: "expiring_30_days" },
    { label: "Healthy", value: "healthy" },
  ],
};

/** One id per row, shared by the table and its selection. */
const getCertificateRowId = (certificate: SSLCertificateListItem): string =>
  certificate.certificateXref || certificate.domain;

const getCertificateSelectionLabel = (
  certificate: SSLCertificateListItem,
): string => `Select ${certificate.domain}`;

const BULK_DELETE_SELECTION_SHORTCUTS = [
  { label: "Select all failed", pickRows: pickDeletableFailedCertificates },
];

const HIDDEN_TABLE_COLUMNS = [
  "renewalWindow",
  "caProvider",
  "issuer",
  "managementState",
  "validFrom",
];

function MobileCertificateCards({
  certificates,
  canDelete,
  canDeploy,
  canManageCredentialConfig,
  canRenew,
  canRevoke,
  isCertRenewalEnabled,
  isCertRevocationEnabled,
  cardPage,
  emptyState,
  onOpenManualDns,
  onManageCredentialConfig,
  onDelete,
  onPageChange,
  onRenew,
  onRevoke,
  onDownload,
}: {
  certificates: SSLCertificateListItem[];
  emptyState?: React.ReactNode;
  canDelete: boolean;
  canDeploy: boolean;
  canManageCredentialConfig: boolean;
  canRenew: boolean;
  canRevoke: boolean;
  isCertRenewalEnabled: boolean;
  isCertRevocationEnabled: boolean;
  cardPage: number;
  onOpenManualDns: (certificate: SSLCertificateListItem) => void;
  onManageCredentialConfig: (certificate: SSLCertificateListItem) => void;
  onDelete: (certificate: SSLCertificateListItem) => void;
  onPageChange: (page: number) => void;
  onRenew: (certificateXref: string) => void;
  onRevoke: (certificate: SSLCertificateListItem) => void;
  onDownload?: (certificate: SSLCertificateListItem) => void;
}) {
  const pageCount = Math.max(
    1,
    Math.ceil(certificates.length / CARD_PAGE_SIZE),
  );
  const currentPage = Math.min(cardPage, pageCount);
  const paginatedCertificates = certificates.slice(
    (currentPage - 1) * CARD_PAGE_SIZE,
    currentPage * CARD_PAGE_SIZE,
  );

  if (certificates.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          {emptyState ??
            "No certificates found. Adjust the filters or issue a new certificate to get started."}
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {paginatedCertificates.map((certificate) => (
          <Card
            key={certificate.certificateXref || certificate.domain}
            className="overflow-hidden"
          >
            <CardHeader className="relative flex flex-row items-start justify-between gap-3 space-y-0 px-4 pt-4 pb-3">
              <div className="min-w-0 space-y-2">
                <div className="flex items-center gap-2">
                  <CertificateStatusIcon status={certificate.status} />
                  {canViewCertificateDetails(certificate) ? (
                    <Link
                      href={getCertificateDetailHref(certificate)}
                      className="block truncate text-base font-semibold text-foreground transition-colors hover:text-primary"
                    >
                      {certificate.domain}
                    </Link>
                  ) : (
                    <span className="block truncate text-base font-semibold text-foreground">
                      {certificate.domain}
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap gap-2">
                  <div className="flex justify-start">
                    <Badge
                      variant={getCertificateStatusBadgeVariant(
                        certificate.status,
                      )}
                      textOnly
                    >
                      {formatCertificateStatusLabel(certificate.status)}
                    </Badge>
                  </div>
                  {certificate.caProvider ? (
                    <div className="flex justify-start">
                      <Badge
                        variant="secondary"
                        textOnly
                        className="text-xs font-medium"
                      >
                        {getProviderPresentation(certificate.caProvider).label}
                      </Badge>
                    </div>
                  ) : null}
                  {getCoverageSummary(certificate).map((item) => (
                    <div key={item} className="flex justify-start">
                      <Badge
                        variant="secondary"
                        textOnly
                        className="text-xs font-medium"
                      >
                        {item}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
              <CertificateActions
                certificate={certificate}
                canDelete={canDelete}
                canDeploy={canDeploy}
                canManageCredentialConfig={canManageCredentialConfig}
                canRenew={canRenew}
                canRevoke={canRevoke}
                isCertRenewalEnabled={isCertRenewalEnabled}
                isCertRevocationEnabled={isCertRevocationEnabled}
                onOpenManualDns={onOpenManualDns}
                onManageCredentialConfig={onManageCredentialConfig}
                onDelete={onDelete}
                onRenew={onRenew}
                onRevoke={onRevoke}
                onDownload={onDownload}
              />
            </CardHeader>
            <CardContent className="px-4 pt-0 pb-4">
              <dl className="space-y-2 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-xs text-muted-foreground">Valid from</dt>
                  <dd className="text-right">
                    <div className="font-medium text-foreground">
                      {formatDate(certificate.validFrom || null)}
                    </div>
                    <ExpiryHint validTo={certificate.validTo ?? null} />
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-xs text-muted-foreground">Valid until</dt>
                  <dd className="font-medium text-foreground">
                    {certificate.validTo
                      ? formatDate(certificate.validTo)
                      : "Pending issuance"}
                  </dd>
                </div>
                <div className="flex items-start justify-between gap-3">
                  <dt className="text-xs text-muted-foreground">Management</dt>
                  <dd className="flex flex-col items-end space-y-2 text-right">
                    <ToolTipCard
                      value={
                        <div className="max-w-56 text-right text-xs text-muted-foreground">
                          {getManagementSummary(certificate)}
                        </div>
                      }
                    >
                      <div className="flex justify-end">
                        <p
                          className={cn(
                            certificate.managementState === "fully-managed"
                              ? "status-success-text"
                              : "status-warning-text",
                          )}
                        >
                          {getCertificateManagementLabel(
                            certificate.managementState || "manual",
                          )}
                        </p>
                      </div>
                    </ToolTipCard>
                  </dd>
                </div>
              </dl>
            </CardContent>
            {certificate.status === "ACTIVE" && certificate.validTo ? (
              <CardFooter className="flex min-h-10 items-center justify-between px-4 py-3">
                <div>
                  <ExpiringSoonBadge validTo={certificate.validTo} />
                </div>
              </CardFooter>
            ) : null}
          </Card>
        ))}
      </div>

      {pageCount > 1 ? (
        <div className="flex items-center justify-between rounded-lg border bg-card px-4 py-3">
          <div className="text-sm text-muted-foreground">
            Page {currentPage} of {pageCount}
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage === 1}
              onClick={() => onPageChange(currentPage - 1)}
            >
              <CaretLeftIcon className="mr-1 h-4 w-4" />
              Prev
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage === pageCount}
              onClick={() => onPageChange(currentPage + 1)}
            >
              Next
              <CaretRightIcon className="ml-1 h-4 w-4" />
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function CertManagerDashboard() {
  const searchParams = useSearchParams();
  const { user, isLoading: isLoadingAuth } = useAuth();
  const isCertIssuanceEnabled = useIsFeatureEnabled("CERTIFICATE_ISSUANCE");
  const isCertRenewalEnabled = useIsFeatureEnabled("CERTIFICATE_RENEWAL");
  const isCertRevocationEnabled = useIsFeatureEnabled("CERTIFICATE_REVOCATION");
  const isCertDeploymentEnabled = useIsFeatureEnabled("CERTIFICATE_DEPLOYMENT");
  const isMobile = useIsMobile();
  const canView = canViewCertificates(user);
  const canCreate = canCreateCertificates(user);
  const canDeploy = isCertDeploymentEnabled && canCreateDeployments(user);
  const canViewDeploymentList =
    isCertDeploymentEnabled && canViewDeployments(user);
  const canRenew = canRenewCertificates(user);
  const canRevoke = canRevokeCertificates(user);
  const canDelete = canDeleteCertificates(user);
  const canManageCredentialConfig = canUpdateCredentials(user);
  const canDownloadCertificates = useCanDownloadCertificates();
  // The list carries no per-certificate formats, so this alone gates the key formats.
  const canDownloadPrivateKey = canExportPrivateKey(user);

  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const [managementCertificate, setManagementCertificate] =
    useState<SSLCertificateListItem | null>(null);
  const [manualDnsDraft, setManualDnsDraft] =
    useState<ManualTxtRecordsDialogState | null>(null);
  const [downloadTarget, setDownloadTarget] =
    useState<CertificateDownloadTarget | null>(null);
  // Losing access (say a 423) unmounts the dialog; drop its target too so
  // regaining access later in the session does not reopen it unasked.
  const [prevCanDownload, setPrevCanDownload] = useState(
    canDownloadCertificates,
  );
  if (canDownloadCertificates !== prevCanDownload) {
    setPrevCanDownload(canDownloadCertificates);
    if (!canDownloadCertificates) setDownloadTarget(null);
  }
  const [cardSearchTerm, setCardSearchTerm] = useState("");
  const [cardPage, setCardPage] = useState(1);
  const [preferredView, setPreferredView] = useState<ViewMode>("table");

  const certificatesQuery = useProgressiveCertificateList();
  const renewCertificate = useRenewCertificate();
  const revokeCertificate = useRevokeCertificate();
  const deleteCertificate = useDeletePendingSSLCertificate();
  const bulkDelete = useBulkDeleteCertificates();
  // The ids outlive the dialog's close so its exit animation keeps its count.
  const [bulkDeleteIds, setBulkDeleteIds] = useState<string[]>([]);
  const [isBulkDeleteOpen, setIsBulkDeleteOpen] = useState(false);
  const getTxtRecords = useGetTxtRecords();
  const validateDns = useCompleteDnsChallenge();

  const certificates = useMemo(
    () => sortCertificatesByAttention(certificatesQuery.data || [], new Date()),
    [certificatesQuery.data],
  );
  // The URL owns the filters for both views; the table and the cards only
  // read them and report changes back.
  const { tableFilters, replaceTableFilters, setTableFilter } =
    useCertificateTableUrlFilters();
  const tableStatusFilter = tableFilters.status ?? "";
  const cardStatusFilter = tableFilters.status ?? "all";
  const cardProviderFilter = tableFilters.caProvider ?? "all";
  const [initialTableSearchTerm] = useState(
    () => searchParams.get("search")?.trim() ?? "",
  );

  // Selection is cleared whenever the rows a bulk delete could touch change, so
  // it never carries ids the list no longer shows as deletable. Status polling
  // that changes nothing deletable, and pages still arriving, leave it alone.
  const isInventoryComplete = certificatesQuery.isInventoryComplete;
  const deletableRowIds = useMemo(
    () =>
      certificates.filter(canDeleteCertificateRecord).map(getCertificateRowId),
    [certificates],
  );
  const [rowSelection, setRowSelection] = useInventoryRowSelection(
    deletableRowIds,
    isInventoryComplete,
  );

  useEffect(() => {
    try {
      const stored = readCertificateViewPreference(window.localStorage);
      if (stored) {
        setPreferredView(stored);
      }
    } catch {
      // Ignore storage access failures and keep the default view.
    }
  }, []);

  useEffect(() => {
    try {
      writeCertificateViewPreference(window.localStorage, preferredView);
    } catch {
      // Ignore storage access failures and keep the in-memory preference.
    }
  }, [preferredView]);

  useEffect(() => {
    setCardPage(1);
  }, [cardProviderFilter, cardSearchTerm, cardStatusFilter]);

  const metrics = useMemo(
    () => computeCertificateDashboardMetrics(certificates, new Date()),
    [certificates],
  );
  const animatedTotal = useAnimatedCount(metrics.total);
  const animatedActive = useAnimatedCount(metrics.active);
  const animatedExpiring = useAnimatedCount(metrics.expiring);
  const animatedPending = useAnimatedCount(metrics.pending);

  const providerOptions = useMemo(
    () => getCertificateProviderOptions(certificates),
    [certificates],
  );
  const issuerOptions = useMemo(
    () => getCertificateIssuerOptions(certificates),
    [certificates],
  );
  const managementStateFilterOptions = useMemo(
    () => [
      { label: "All modes", value: "all" },
      { label: "Manual", value: "manual" },
      { label: "DNS managed", value: "dns-managed" },
      ...(isCertDeploymentEnabled
        ? [
            {
              label: "Deployment managed",
              value: "deployment-managed",
            },
            { label: "Fully managed", value: "fully-managed" },
          ]
        : []),
    ],
    [isCertDeploymentEnabled],
  );

  const cardFilteredCertificates = useMemo(
    () =>
      filterCertificatesForCardView({
        certificates,
        searchTerm: cardSearchTerm,
        statusFilter: cardStatusFilter,
        providerFilter: cardProviderFilter,
        issuerFilter: tableFilters.issuer ?? "all",
      }),
    [
      certificates,
      cardProviderFilter,
      cardSearchTerm,
      cardStatusFilter,
      tableFilters.issuer,
    ],
  );

  const openManualDnsDialog = useCallback(
    async (certificate: SSLCertificateListItem) => {
      if (!certificate.certificateXref) {
        return;
      }

      const txtRecords = await getTxtRecords.mutateAsync({
        certificateXref: certificate.certificateXref,
      });

      setManualDnsDraft({
        certificateXref: certificate.certificateXref,
        domain: certificate.domain,
        txtRecords,
      });
    },
    [getTxtRecords],
  );

  const openDownloadDialog = useCallback(
    (certificate: SSLCertificateListItem) => {
      if (certificate.certificateXref) {
        setDownloadTarget({
          certificateXref: certificate.certificateXref,
          domain: certificate.domain,
          isWildcard: certificate.wildcard === true,
          keyCustody: certificate.keyCustody,
        });
      }
    },
    [],
  );
  const closeDownloadDialog = useCallback(() => setDownloadTarget(null), []);
  const handleDownload = canDownloadCertificates
    ? openDownloadDialog
    : undefined;

  const columns = useMemo<ColumnDef<SSLCertificateListItem>[]>(
    () => [
      {
        accessorKey: "domain",
        header: "Domain",
        size: 320,
        cell: ({ row }) => {
          const certificate = row.original;
          const provider = certificate.caProvider
            ? getProviderPresentation(certificate.caProvider).label
            : null;
          const management = getCertificateManagementLabel(
            certificate.managementState || "manual",
          );
          return (
            <div className="min-w-0">
              {canViewCertificateDetails(certificate) ? (
                <Link
                  href={getCertificateDetailHref(certificate)}
                  title={certificate.domain}
                  className="block truncate font-medium text-foreground hover:text-primary"
                >
                  {certificate.domain}
                </Link>
              ) : (
                <span
                  title={certificate.domain}
                  className="block truncate font-medium text-foreground"
                >
                  {certificate.domain}
                </span>
              )}
              <span className="block truncate text-xs text-muted-foreground">
                {[provider, management].filter(Boolean).join(" · ")}
              </span>
            </div>
          );
        },
      },
      {
        accessorKey: "status",
        header: "Status",
        // Exact match: the default substring match would show RENEWAL_FAILED
        // and REVOCATION_FAILED rows under "Failed".
        filterFn: "equalsString",
        cell: ({ row }) => (
          <div className="flex justify-start">
            <Badge
              variant={getCertificateStatusBadgeVariant(row.original.status)}
              textOnly
              className="text-sm font-medium"
            >
              {formatCertificateStatusLabel(row.original.status)}
            </Badge>
          </div>
        ),
      },
      {
        accessorKey: "caProvider",
        header: "Provider",
        filterFn: "equalsString",
        cell: ({ row }) =>
          row.original.caProvider ? (
            <div className="flex justify-start">
              <p>{getProviderPresentation(row.original.caProvider).label}</p>
            </div>
          ) : (
            "-"
          ),
      },
      {
        accessorKey: "issuer",
        header: "Issuer",
        filterFn: "equalsString",
        cell: ({ row }) => row.original.issuer || "-",
      },
      {
        accessorKey: "managementState",
        header: "Management",
        filterFn: "equalsString",
        cell: ({ row }) => (
          <div className="space-y-1">
            <div className="flex justify-start">
              <ToolTipCard
                value={
                  <div className="max-w-56 text-right text-xs text-muted-foreground">
                    {getManagementSummary(row.original)}
                  </div>
                }
              >
                <p className="whitespace-nowrap capitalize">
                  {getCertificateManagementLabel(
                    row.original.managementState || "manual",
                  )}
                  {row.original.managementState === "manual" ||
                  row.original.managementState === "dns-managed" ||
                  row.original.managementState === "deployment-managed" ? (
                    <InfoIcon className="ml-1 inline size-3 status-warning-text" />
                  ) : null}
                </p>
              </ToolTipCard>
            </div>
          </div>
        ),
      },
      {
        id: "renewalWindow",
        accessorFn: (row) => getCertificateRenewalBucket(row),
        header: "Renewal window",
        enableHiding: true,
        cell: () => null,
      },
      {
        accessorKey: "validFrom",
        header: "Valid from",
        enableSorting: true,
        sortingFn: (rowA, rowB, columnId) =>
          compareDateValues(rowA.getValue(columnId), rowB.getValue(columnId)),
        cell: ({ row }) => (
          <div className="space-y-1">
            <div className="text-sm text-foreground">
              {formatDate(row.original.validFrom || null)}
            </div>
            <ExpiryHint validTo={row.original.validTo ?? null} />
          </div>
        ),
      },
      {
        accessorKey: "validTo",
        header: "Valid until",
        enableSorting: true,
        sortingFn: (rowA, rowB, columnId) =>
          compareDateValues(rowA.getValue(columnId), rowB.getValue(columnId)),
        cell: ({ row }) => {
          const validTo = row.original.validTo;
          if (!validTo) {
            return "-";
          }

          const remainingDays = getRemainingDays(validTo);
          const expiresLabel =
            remainingDays === null
              ? null
              : remainingDays <= 0
                ? "Expired"
                : `Expires in ${remainingDays} day${remainingDays === 1 ? "" : "s"}`;

          const expiresClassName =
            remainingDays === null
              ? "text-muted-foreground"
              : remainingDays <= 7
                ? "status-danger-text"
                : remainingDays <= 30
                  ? "status-warning-text"
                  : "text-muted-foreground";

          return (
            <div className="space-y-1">
              <div className="text-sm text-foreground">
                {formatDate(validTo)}
              </div>
              {expiresLabel ? (
                <div className={cn("text-[12px] leading-4", expiresClassName)}>
                  {expiresLabel}
                </div>
              ) : null}
            </div>
          );
        },
      },
      {
        id: "actions",
        enableHiding: false,
        header: () => <span className="sr-only">Actions</span>,
        cell: ({ row }) => (
          <div className="flex justify-end">
            <CertificateActions
              certificate={row.original}
              canDelete={canDelete}
              canDeploy={canDeploy}
              canManageCredentialConfig={canManageCredentialConfig}
              canRenew={canRenew}
              canRevoke={canRevoke}
              isCertRenewalEnabled={isCertRenewalEnabled}
              isCertRevocationEnabled={isCertRevocationEnabled}
              onOpenManualDns={openManualDnsDialog}
              onManageCredentialConfig={(certificate) =>
                setManagementCertificate(certificate)
              }
              onDelete={(certificate) =>
                setPendingAction({
                  type: "delete",
                  certificate,
                })
              }
              onRenew={(certificateXref) =>
                renewCertificate.mutate({
                  certificateXref,
                })
              }
              onRevoke={(certificate) =>
                setPendingAction({
                  type: "revoke",
                  certificate,
                })
              }
              onDownload={handleDownload}
            />
          </div>
        ),
      },
    ],
    [
      canDelete,
      canDeploy,
      canManageCredentialConfig,
      canRenew,
      canRevoke,
      isCertRenewalEnabled,
      isCertRevocationEnabled,
      handleDownload,
      openManualDnsDialog,
      renewCertificate,
    ],
  );

  const isBulkDeleteRunning = bulkDelete.isRunning;
  const bulkDeleteActions = useMemo(
    () => [
      {
        label: (_count: number, rows: SSLCertificateListItem[]) =>
          `Delete selected (${collectDeletableDomainIds(rows).length})`,
        icon: TrashIcon,
        variant: "destructive" as const,
        disabled: isBulkDeleteRunning,
        onClick: (rows: SSLCertificateListItem[]) => {
          setBulkDeleteIds(collectDeletableDomainIds(rows));
          setIsBulkDeleteOpen(true);
        },
      },
    ],
    [isBulkDeleteRunning],
  );
  // Until every page is in, "Select all failed" would miss failures on later
  // pages and a delete would act on a partial picture; picking rows still works.
  const bulkSelectionPendingMessage = isInventoryComplete
    ? undefined
    : "Loading all certificates…";

  const confirmBulkDelete = async () => {
    const outcome = await bulkDelete.deleteDomains(bulkDeleteIds);
    if (!outcome) return;
    setIsBulkDeleteOpen(false);
    setRowSelection({});
  };

  // Closing mid-run stops it: in-flight deletes finish, no new ones start, and
  // the summary toast still reports what happened.
  const closeBulkDeleteDialog = () => {
    bulkDelete.stop();
    setIsBulkDeleteOpen(false);
  };

  if (isLoadingAuth || certificatesQuery.isLoading) {
    return <CertificatesSkeleton />;
  }

  if (certificatesQuery.error && !certificatesQuery.data) {
    return (
      <div className="p-6">
        <SomethingWentWrong
          title="Unable to load certificates"
          description="The certificate service did not respond."
          reference={errorReference(certificatesQuery.error)}
          onRetry={() => void certificatesQuery.refetch()}
        />
      </div>
    );
  }

  // Note: CERTIFICATE_ISSUANCE no longer gates the whole page-viewing existing
  // certificates is always allowed (subject to RBAC). The flag only hides the
  // "Issue certificate" CTA further down.
  if (!canView) {
    return (
      <div className="p-6">
        <Unauthorised />
      </div>
    );
  }

  const activeView: ViewMode = isMobile ? "card" : preferredView;
  const canIssue = canCreate && isCertIssuanceEnabled;
  const isInventoryEmpty = certificates.length === 0;
  const firstRunEmptyState = isInventoryEmpty ? (
    <div className="flex flex-col items-center justify-center gap-3 py-6 text-sm text-muted-foreground">
      <p className="font-medium text-foreground">No certificates yet.</p>
      {canIssue ? (
        <Button asChild>
          <Link href="/cert-manager/add">
            <PlusIcon className="h-4 w-4" />
            Issue a certificate
          </Link>
        </Button>
      ) : null}
    </div>
  ) : undefined;

  return (
    <>
      {canDownloadCertificates && downloadTarget ? (
        <LazyDownloadCertificateDialog
          target={downloadTarget}
          canDownloadPrivateKey={canDownloadPrivateKey}
          onClose={closeDownloadDialog}
        />
      ) : null}

      <BulkDeleteCertificatesDialog
        open={isBulkDeleteOpen}
        domainCount={bulkDeleteIds.length}
        progress={bulkDelete.progress}
        onConfirm={() => void confirmBulkDelete()}
        onClose={closeBulkDeleteDialog}
      />

      <CertificateManagementDialog
        certificate={managementCertificate}
        open={Boolean(managementCertificate)}
        onOpenChange={(open) => {
          if (!open) {
            setManagementCertificate(null);
          }
        }}
      />

      <ManualTxtRecordsDialog
        draft={manualDnsDraft}
        open={Boolean(manualDnsDraft)}
        isValidating={validateDns.isPending}
        onOpenChange={(open) => {
          if (!open) {
            setManualDnsDraft(null);
          }
        }}
        onValidate={async (draft) => {
          await validateDns.mutateAsync({
            certificateXref: draft.certificateXref,
          });
          setManualDnsDraft(null);
        }}
      />

      <AlertDialog
        open={Boolean(pendingAction)}
        onOpenChange={(open) => {
          if (!open) {
            setPendingAction(null);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {pendingAction?.type === "delete"
                ? "Delete certificate?"
                : "Revoke certificate?"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {pendingAction?.type === "delete"
                ? "This removes the certificate from the active UI. Existing deployments are not automatically rolled back."
                : "This starts the revoke workflow. The certificate will remain visible while the backend processes the request."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={async () => {
                if (!pendingAction) {
                  return;
                }

                if (pendingAction.type === "delete") {
                  if (!pendingAction.certificate.userDomainCertId) {
                    return;
                  }

                  await deleteCertificate.mutateAsync({
                    userDomainCertId:
                      pendingAction.certificate.userDomainCertId,
                  });
                } else {
                  if (!pendingAction.certificate.certificateXref) {
                    return;
                  }
                  await revokeCertificate.mutateAsync({
                    certificateXref: pendingAction.certificate.certificateXref,
                  });
                }

                setPendingAction(null);
              }}
            >
              Confirm
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <div className="space-y-5 p-5 md:p-6">
        <CertificateInventoryProgress
          isLoading={certificatesQuery.isLoadingAdditionalPages}
          hasError={certificatesQuery.isFetchNextPageError}
          loadedItems={certificatesQuery.loadedItems}
          totalItems={certificatesQuery.totalItems}
          onRetry={() => {
            void certificatesQuery.retryAdditionalPages();
          }}
        />

        <section className="space-y-4 md:space-y-0">
          <div className="flex w-full flex-col gap-6 pb-4">
            <PageHeader
              title="Certificates"
              subtitle="Certificate inventory and lifecycle status."
              actions={
                <div className="flex w-full flex-wrap items-center gap-3 md:justify-end">
                  {canViewDeploymentList ? (
                    <Button asChild variant="outline">
                      <Link href="/cert-manager/deployments">
                        View deployments
                      </Link>
                    </Button>
                  ) : null}
                  {canIssue ? (
                    <Button
                      asChild
                      variant={isInventoryEmpty ? "outline" : "default"}
                    >
                      <Link href="/cert-manager/add">
                        <PlusIcon className="h-4 w-4" />
                        Issue certificate
                      </Link>
                    </Button>
                  ) : null}
                </div>
              }
            />

            <MetricStrip aria-label="Certificate summary">
              <MetricCard
                title="certificates"
                value={animatedTotal}
                icon={ShieldIcon}
              />
              <MetricCard
                title="active"
                value={animatedActive}
                icon={CheckCircleIcon}
                tone="success"
              />
              {isCertRenewalEnabled ? (
                <MetricCard
                  title="expire within 30 days"
                  value={animatedExpiring}
                  icon={WarningIcon}
                  tone="warning"
                />
              ) : null}
              <MetricCard
                title="pending"
                value={animatedPending}
                icon={ClockIcon}
                tone="warning"
              />
              <MetricCard
                title="failed"
                value={metrics.failed}
                icon={WarningIcon}
                tone="danger"
              />
            </MetricStrip>

            {metrics.failed > 0 && tableStatusFilter !== "FAILED" ? (
              <Alert variant="destructive">
                <WarningIcon aria-hidden />
                <AlertTitle>
                  {metrics.failed} certificate{metrics.failed === 1 ? "" : "s"}{" "}
                  failed to issue
                </AlertTitle>
                <AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <span>
                    These domains aren&apos;t covered. Open one to see why it
                    failed, fix the cause, then request it again.
                  </span>
                  <Button asChild variant="destructive" size="sm">
                    <Link href="/cert-manager?status=FAILED">Show failed</Link>
                  </Button>
                </AlertDescription>
              </Alert>
            ) : null}

            {activeView === "card" ? (
              <div className="flex w-full flex-col justify-start gap-4 md:flex-row md:items-center">
                <Input
                  value={cardSearchTerm}
                  onChange={(event) => setCardSearchTerm(event.target.value)}
                  placeholder="Search by domain, provider or issuer"
                  aria-label="Search certificates"
                  className="w-full max-w-md"
                />
                <div className="flex w-full justify-start gap-4 md:w-fit">
                  <Select
                    value={cardStatusFilter}
                    onValueChange={(value) => setTableFilter("status", value)}
                  >
                    <SelectTrigger
                      aria-label="Filter by status"
                      className="w-full max-w-48 min-w-fit"
                    >
                      <SelectValue placeholder="Filter by status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All statuses</SelectItem>
                      {CERTIFICATE_STATUS_FILTER_OPTIONS.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select
                    value={cardProviderFilter}
                    onValueChange={(value) =>
                      setTableFilter("caProvider", value)
                    }
                  >
                    <SelectTrigger
                      aria-label="Filter by provider"
                      className="w-full max-w-48 min-w-fit"
                    >
                      <SelectValue placeholder="Filter by provider" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All providers</SelectItem>
                      {providerOptions.map((provider) => (
                        <SelectItem
                          className="capitalize"
                          key={provider}
                          value={provider}
                        >
                          {provider?.replaceAll("_", " ") || provider}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {!isMobile ? (
                  <ViewSwitcher
                    size="sm"
                    className="md:ml-auto"
                    value={preferredView}
                    onValueChange={setPreferredView}
                  />
                ) : null}
              </div>
            ) : null}
            {activeView === "card" && canDelete ? (
              <p className="-mt-2 text-xs text-muted-foreground">
                {isMobile
                  ? "Bulk delete is available in table view on a larger screen."
                  : "Bulk delete is available in table view."}
              </p>
            ) : null}
          </div>

          {activeView === "table" ? (
            <CustomTable
              viewSwitcher={
                isMobile
                  ? undefined
                  : { value: preferredView, onValueChange: setPreferredView }
              }
              columns={columns}
              data={certificates}
              emptyTableMsg="No certificates found. Try a different filter, or issue a new certificate to get started."
              emptyState={firstRunEmptyState}
              getRowId={getCertificateRowId}
              showColumnVisibility={false}
              searchBy={["domain", "certificateXref", "caProvider", "issuer"]}
              searchPlaceholder="Search by domain, provider or issuer"
              filters={[
                {
                  id: "status",
                  type: "select",
                  label: "Status",
                  placeholder: "Status",
                  options: [
                    { label: "All statuses", value: "all" },
                    ...CERTIFICATE_STATUS_FILTER_OPTIONS,
                  ],
                },
                {
                  id: "caProvider",
                  type: "select",
                  label: "Certificate authority",
                  placeholder: "Provider",
                  options: [
                    { label: "All providers", value: "all" },
                    ...providerOptions.map((provider) => ({
                      label: provider?.replaceAll("_", " ") || provider,
                      value: provider,
                    })),
                  ],
                },
                {
                  id: "issuer",
                  type: "select",
                  label: "Issuer",
                  placeholder: "Issuer",
                  options: [
                    { label: "All issuers", value: "all" },
                    ...issuerOptions.map((issuer) => ({
                      label: issuer,
                      value: issuer,
                    })),
                  ],
                },
                {
                  id: "managementState",
                  type: "select",
                  label: "Management",
                  placeholder: "Management",
                  options: managementStateFilterOptions,
                },
                EXPIRY_FILTER,
              ]}
              defaultFilterValues={tableFilters}
              defaultSearchTerm={initialTableSearchTerm}
              defaultHiddenColumns={HIDDEN_TABLE_COLUMNS}
              onFilterValuesChange={replaceTableFilters}
              selectable={canDelete}
              canSelectRow={canDeleteCertificateRecord}
              getRowSelectionLabel={getCertificateSelectionLabel}
              rowSelection={rowSelection}
              onRowSelectionChange={setRowSelection}
              selectionShortcuts={BULK_DELETE_SELECTION_SHORTCUTS}
              bulkActions={bulkDeleteActions}
              selectionActionsPendingMessage={bulkSelectionPendingMessage}
            />
          ) : (
            <MobileCertificateCards
              certificates={cardFilteredCertificates}
              canDelete={canDelete}
              canDeploy={canDeploy}
              canManageCredentialConfig={canManageCredentialConfig}
              canRenew={canRenew}
              canRevoke={canRevoke}
              isCertRenewalEnabled={isCertRenewalEnabled}
              isCertRevocationEnabled={isCertRevocationEnabled}
              cardPage={cardPage}
              emptyState={firstRunEmptyState}
              onOpenManualDns={openManualDnsDialog}
              onManageCredentialConfig={setManagementCertificate}
              onDelete={(certificate) =>
                setPendingAction({
                  type: "delete",
                  certificate,
                })
              }
              onPageChange={setCardPage}
              onRenew={(certificateXref) =>
                renewCertificate.mutate({
                  certificateXref,
                })
              }
              onRevoke={(certificate) =>
                setPendingAction({
                  type: "revoke",
                  certificate,
                })
              }
              onDownload={handleDownload}
            />
          )}
        </section>
      </div>
    </>
  );
}

function ExpiryHint({ validTo }: { validTo: string | null }) {
  const expiry = getExpiryLabel(validTo, { pendingLabel: "" });

  if (!validTo || expiry.tone !== "critical") {
    return null;
  }

  return (
    <div className="text-xs font-medium status-danger-text">{expiry.text}</div>
  );
}

function ExpiringSoonBadge({ validTo }: { validTo: string }) {
  const expiry = getExpiryLabel(validTo);
  if (expiry.tone !== "critical") {
    return null;
  }

  return (
    <Badge variant="warning" textOnly className="text-xs font-medium">
      {expiry.text}
    </Badge>
  );
}

function CertificatesSkeleton() {
  return (
    <div
      className="space-y-5 p-5 md:p-6"
      role="status"
      aria-label="Loading certificates"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-2">
          <Skeleton className="h-7 w-48" />
          <Skeleton className="h-4 w-72" />
        </div>
        <Skeleton className="h-10 w-40 rounded-full" />
      </div>
      <Skeleton className="h-5 w-96 max-w-full" />
      <div className="flex gap-2">
        <Skeleton className="h-9 w-72 rounded-(--radius-control)" />
        <Skeleton className="h-8 w-24 rounded-full" />
        <Skeleton className="h-8 w-32 rounded-full" />
      </div>
      <Skeleton className="h-112 rounded-[10px]" />
    </div>
  );
}
