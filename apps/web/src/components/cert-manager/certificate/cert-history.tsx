// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { ColumnDef } from "@tanstack/react-table";

import { useGetCertificateHistory } from "@/hooks/ssl";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { canViewDeployments } from "@/lib/authz";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { useAuthStore } from "@/stores/auth-store";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import { fuzzySearch } from "@/lib/fuzzy-search";
import type {
  CertificateHistoryItem,
  CertificateHistoryPage,
} from "@/types/cert-manager";
import type { SSLCertificateDetails } from "@/types/ssl";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import { Input } from "@/components/ui/input";
import { ViewSwitcher } from "@/components/ui/view-switcher";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { CertDetailss } from "./cert-details";
import {
  ArrowSquareOutIcon,
  DotsThreeIcon,
  MagnifyingGlassIcon,
} from "@phosphor-icons/react";
import { getPrimaryDnsConfigXref } from "@/lib/certificate-management";
import { formatDate } from "@/lib/utils";
import {
  getCertificateStatusLabel,
  getCertificateStatusTone,
  normalizeCertificateStatus,
} from "@/lib/cert-manager/certificate-status";

const HISTORY_SEARCH_KEYS = [
  "certificateXref",
  "status",
  "validFrom",
  "validTo",
];

const HISTORY_STATUS_TONE_CLASS: Record<string, string> = {
  success: "status-success-text",
  warning: "status-warning-text",
  destructive: "status-danger-text",
  secondary: "text-muted-foreground",
};

const getHistoryStatusBadgeClass = (status: string): string =>
  normalizeCertificateStatus(status) === "RENEW_SUCCESS"
    ? "status-info-text"
    : HISTORY_STATUS_TONE_CLASS[getCertificateStatusTone(status)];

const formatStatus = getCertificateStatusLabel;

const formatHistoryDate = (value?: string | null): string =>
  formatDate(value ?? null);

const RENEWAL_TRIGGER_LABEL: Record<string, string> = {
  SCHEDULED: "Scheduled renewal",
  MANUAL: "Manual renewal",
};

const getRenewalTriggerLabel = (item: CertificateHistoryItem): string | null =>
  item.renewalTrigger
    ? (RENEWAL_TRIGGER_LABEL[item.renewalTrigger] ?? null)
    : null;

interface CertHistoryProps {
  certificate: SSLCertificateDetails;
}

const toTimestamp = (value?: string | null): number =>
  value ? Date.parse(value) || 0 : 0;

const getCurrentCertificateXref = (
  items: CertificateHistoryItem[],
): string | undefined => {
  if (items.length === 0) {
    return undefined;
  }

  const activeItems = items.filter((item) => item.status === "ACTIVE");
  const pool = activeItems.length > 0 ? activeItems : items;

  return [...pool].sort((left, right) => {
    return (
      toTimestamp(right.validTo) - toTimestamp(left.validTo) ||
      toTimestamp(right.validFrom) - toTimestamp(left.validFrom)
    );
  })[0]?.certificateXref;
};

const getHistoryDeploymentHref = (item: CertificateHistoryItem): string => {
  const params = new URLSearchParams();
  params.set("domain", item.domain);
  params.set("certificateXref", item.certificateXref);
  return `/cert-manager/deployments/${encodeURIComponent(item.userDomainCertId)}?${params.toString()}`;
};

export function CertHistory({ certificate }: CertHistoryProps) {
  const isDeploymentOn = useIsFeatureEnabled(
    FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT,
  );
  const canSeeDeployments = useAuthStore((state) =>
    canViewDeployments(state.user),
  );
  const canOpenDeployments = isDeploymentOn && canSeeDeployments;
  const historyQuery = useGetCertificateHistory(certificate.userDomainCertId);
  const data: CertificateHistoryPage | undefined = historyQuery.data;
  const isLoading = historyQuery.isLoading;
  const isError = historyQuery.isError;
  const [selectedHistoryItem, setSelectedHistoryItem] =
    useState<CertificateHistoryItem | null>(null);
  const hasHistoryIdentifier = Boolean(certificate.userDomainCertId);
  const currentCertificateXref = useMemo(
    () => getCurrentCertificateXref(data?.items ?? []),
    [data?.items],
  );
  const [viewMode, setViewMode] = useResponsiveViewMode({
    storageKey: "cert-history_view",
  });
  const [cardSearchTerm, setCardSearchTerm] = useState("");
  const cardItems = useMemo(() => {
    const items = data?.items ?? [];
    const term = cardSearchTerm.trim();
    if (!term) {
      return items;
    }
    return fuzzySearch(term, items, HISTORY_SEARCH_KEYS);
  }, [cardSearchTerm, data?.items]);

  const columns = useMemo<ColumnDef<CertificateHistoryItem>[]>(
    () => [
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => (
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                textOnly
                className={getHistoryStatusBadgeClass(row.original.status)}
              >
                {formatStatus(row.original.status)}
              </Badge>
              {row.original.certificateXref === currentCertificateXref ? (
                <Badge
                  variant="outline"
                  className="text-[10px] text-muted-foreground"
                >
                  current
                </Badge>
              ) : null}
              {row.original.certificateXref === certificate.certificateXref &&
              row.original.certificateXref !== currentCertificateXref ? (
                <Badge
                  variant="outline"
                  className="text-[10px] text-muted-foreground"
                >
                  viewing
                </Badge>
              ) : null}
            </div>
            {getRenewalTriggerLabel(row.original) ? (
              <p className="text-xs text-muted-foreground">
                {getRenewalTriggerLabel(row.original)}
              </p>
            ) : null}
          </div>
        ),
      },
      {
        accessorKey: "certificateXref",
        header: "Certificate",
        cell: ({ row }) => (
          <div className="space-y-1">
            <button
              type="button"
              className="text-left font-mono text-xs text-primary hover:underline"
              onClick={() => setSelectedHistoryItem(row.original)}
            >
              {row.original.certificateXref}
            </button>
          </div>
        ),
      },
      {
        id: "coverage",
        header: "Coverage",
        cell: ({ row }) => {
          const sanCount = row.original.sanDomains?.length ?? 0;
          return (
            <div className="space-y-1 text-sm">
              <div>{row.original.wildcard ? "Wildcard" : "Single domain"}</div>
              <div className="text-xs text-muted-foreground">
                {row.original.san
                  ? `${sanCount} SAN entries`
                  : "No SAN entries"}
              </div>
            </div>
          );
        },
      },
      {
        id: "crypto",
        header: "Crypto",
        cell: ({ row }) => (
          <div className="space-y-1 text-sm">
            <div>{row.original.certType ?? "Type not provided"}</div>
            <div className="text-xs text-muted-foreground">
              {[
                row.original.publicKeyAlgorithm,
                row.original.keySize ? `${row.original.keySize}-bit` : null,
              ]
                .filter(Boolean)
                .join(" · ") || "Crypto details not provided"}
            </div>
          </div>
        ),
      },
      {
        id: "credentials",
        header: "Credentials",
        cell: ({ row }) => {
          const dnsConfigXref = getPrimaryDnsConfigXref(
            row.original.dnsConfigXref ?? undefined,
          );
          return (
            <div className="space-y-1 text-sm">
              <div>{dnsConfigXref ? "DNS linked" : "No DNS ref"}</div>
              <div className="text-xs text-muted-foreground">
                {row.original.deploymentCredentialXrefs?.length
                  ? `${row.original.deploymentCredentialXrefs.length} deployment refs`
                  : "No deployment refs"}
              </div>
            </div>
          );
        },
      },
      {
        id: "actions",
        header: () => <div className="text-right">Actions</div>,
        cell: ({ row }) => (
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              size="iconSm"
              onClick={() => setSelectedHistoryItem(row.original)}
              aria-label="View history details"
            >
              <DotsThreeIcon className="size-4" aria-hidden />
            </Button>
            {canOpenDeployments ? (
              <Button variant="outline" size="sm" asChild>
                <Link href={getHistoryDeploymentHref(row.original)}>
                  Deployments
                </Link>
              </Button>
            ) : null}
          </div>
        ),
      },
    ],
    [canOpenDeployments, certificate.certificateXref, currentCertificateXref],
  );

  return (
    <div className="space-y-6">
      <HistoryCertificateDialog
        certificate={certificate}
        item={selectedHistoryItem}
        canOpenDeployments={canOpenDeployments}
        onClose={() => setSelectedHistoryItem(null)}
      />

      <div>
        <h3 className="text-xl font-semibold">Renewal history</h3>
        <p className="text-sm text-muted-foreground">
          Certificate records for{" "}
          <span className="font-medium">{certificate.domain}</span>, including
          prior renewals and state transitions.
        </p>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : !hasHistoryIdentifier ? (
        <Alert className="bg-card">
          <AlertTitle>History not available yet</AlertTitle>
          <AlertDescription>
            This certificate does not include a history.
          </AlertDescription>
        </Alert>
      ) : isError ? (
        <Alert className="border-destructive/20 bg-destructive/5">
          <AlertTitle>Failed to load history</AlertTitle>
          <AlertDescription>
            Could not fetch the renewal history for this certificate. Please try
            refreshing the page.
          </AlertDescription>
        </Alert>
      ) : !data || data.items.length === 0 ? (
        <Alert className="bg-card">
          <AlertTitle>No history available</AlertTitle>
          <AlertDescription>
            No earlier certificate records were found for this domain.
          </AlertDescription>
        </Alert>
      ) : (
        <div className="space-y-4">
          {viewMode === "table" ? (
            <CustomTable
              viewSwitcher={{ value: viewMode, onValueChange: setViewMode }}
              columns={columns}
              data={data.items}
              emptyTableMsg="No certificate history records found."
              getRowId={(row) => row.certificateXref}
              pageSize={10}
              searchBy={HISTORY_SEARCH_KEYS}
              searchPlaceholder="Search by status or certificate ref..."
            />
          ) : (
            <>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="relative flex-1 sm:max-w-sm">
                  <MagnifyingGlassIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={cardSearchTerm}
                    onChange={(event) => setCardSearchTerm(event.target.value)}
                    placeholder="Search by status or certificate ref..."
                    className="pr-3 pl-9"
                    aria-label="Search renewal history"
                  />
                </div>
                <ViewSwitcher
                  value={viewMode}
                  onValueChange={setViewMode}
                  showLabels={false}
                />
              </div>
              <CertHistoryGrid
                items={cardItems}
                certificate={certificate}
                currentCertificateXref={currentCertificateXref}
                canOpenDeployments={canOpenDeployments}
                onViewDetails={setSelectedHistoryItem}
              />
            </>
          )}
        </div>
      )}
    </div>
  );
}

function CertHistoryGrid({
  items,
  certificate,
  currentCertificateXref,
  canOpenDeployments,
  onViewDetails,
}: {
  items: CertificateHistoryItem[];
  certificate: SSLCertificateDetails;
  currentCertificateXref?: string;
  /** CERTIFICATE_DEPLOYMENT is on and the user may view deployments. */
  canOpenDeployments: boolean;
  onViewDetails: (item: CertificateHistoryItem) => void;
}) {
  if (items.length === 0) {
    return (
      <Alert className="bg-card">
        <AlertTitle>No records matched</AlertTitle>
        <AlertDescription>
          Adjust the search term to find certificate history records.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-4">
      {items.map((item) => {
        const sanCount = item.sanDomains?.length ?? 0;
        const dnsConfigXref = getPrimaryDnsConfigXref(
          item.dnsConfigXref ?? undefined,
        );
        const deploymentRefCount = item.deploymentCredentialXrefs?.length ?? 0;
        const isCurrent = item.certificateXref === currentCertificateXref;
        const isViewing =
          item.certificateXref === certificate.certificateXref && !isCurrent;
        return (
          <article
            key={item.certificateXref}
            className="flex min-w-0 flex-col overflow-hidden rounded-lg border border-border bg-card"
          >
            <div className="space-y-3 px-4 pt-4 pb-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 space-y-1">
                  <p className="truncate text-base font-semibold text-foreground">
                    {item.domain}
                  </p>
                  <button
                    type="button"
                    className="block max-w-full truncate text-left font-mono text-xs text-primary underline-offset-4 hover:underline"
                    onClick={() => onViewDetails(item)}
                  >
                    {item.certificateXref}
                  </button>
                </div>
                <Badge
                  variant="outline"
                  textOnly
                  className={`shrink-0 ${getHistoryStatusBadgeClass(item.status)}`}
                >
                  {formatStatus(item.status)}
                </Badge>
              </div>

              {getRenewalTriggerLabel(item) ? (
                <p className="text-xs text-muted-foreground">
                  {getRenewalTriggerLabel(item)}
                </p>
              ) : null}

              {isCurrent || isViewing ? (
                <div className="flex flex-wrap gap-2">
                  {isCurrent ? (
                    <Badge
                      variant="outline"
                      className="text-[10px] text-muted-foreground"
                    >
                      Current
                    </Badge>
                  ) : null}
                  {isViewing ? (
                    <Badge variant="outline" className="text-[10px]">
                      Viewing
                    </Badge>
                  ) : null}
                </div>
              ) : null}
            </div>

            <div className="flex flex-1 flex-col px-4 pb-4">
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
                <div className="min-w-0 space-y-1">
                  <dt className="text-xs text-muted-foreground">Valid from</dt>
                  <dd className="truncate font-medium text-foreground">
                    {formatHistoryDate(item.validFrom)}
                  </dd>
                </div>
                <div className="min-w-0 space-y-1">
                  <dt className="text-xs text-muted-foreground">Valid until</dt>
                  <dd className="truncate font-medium text-foreground">
                    {formatHistoryDate(item.validTo)}
                  </dd>
                </div>
                <div className="min-w-0 space-y-1">
                  <dt className="text-xs text-muted-foreground">Coverage</dt>
                  <dd className="min-w-0">
                    <div className="font-medium text-foreground">
                      {item.wildcard ? "Wildcard" : "Single domain"}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {item.san ? `${sanCount} SAN entries` : "No SAN entries"}
                    </div>
                  </dd>
                </div>
                <div className="min-w-0 space-y-1">
                  <dt className="text-xs text-muted-foreground">Crypto</dt>
                  <dd className="min-w-0">
                    <div className="truncate font-medium text-foreground">
                      {item.certType ?? "Type not provided"}
                    </div>
                    <div className="truncate text-xs text-muted-foreground">
                      {[
                        item.publicKeyAlgorithm,
                        item.keySize ? `${item.keySize}-bit` : null,
                      ]
                        .filter(Boolean)
                        .join(" / ") || "Crypto details not provided"}
                    </div>
                  </dd>
                </div>
                <div className="col-span-2 min-w-0 space-y-1">
                  <dt className="text-xs text-muted-foreground">Automation</dt>
                  <dd className="min-w-0">
                    <div className="font-medium text-foreground">
                      {dnsConfigXref ? "DNS linked" : "No DNS reference"}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {deploymentRefCount > 0
                        ? `${deploymentRefCount} deployment refs`
                        : "No deployment refs"}
                    </div>
                  </dd>
                </div>
              </dl>
            </div>

            <div className="mt-auto flex flex-wrap gap-2 border-t border-border px-4 py-3">
              {canOpenDeployments ? (
                <Button variant="outline" size="sm" className="flex-1" asChild>
                  <Link href={getHistoryDeploymentHref(item)}>Deployments</Link>
                </Button>
              ) : null}
              <Button
                size="sm"
                className="flex-1"
                onClick={() => onViewDetails(item)}
              >
                <DotsThreeIcon className="size-4" />
                Details
              </Button>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function HistoryCertificateDialog({
  certificate,
  item,
  canOpenDeployments,
  onClose,
}: {
  certificate: SSLCertificateDetails;
  item: CertificateHistoryItem | null;
  canOpenDeployments: boolean;
  onClose: () => void;
}) {
  const [visibleItem, setVisibleItem] = useState<CertificateHistoryItem | null>(
    item,
  );
  const closeTimerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!item) {
      return;
    }

    if (closeTimerRef.current) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }

    setVisibleItem(item);
  }, [item]);

  useEffect(() => {
    return () => {
      if (closeTimerRef.current) {
        window.clearTimeout(closeTimerRef.current);
      }
    };
  }, []);

  const historyCertificate = useMemo<SSLCertificateDetails | undefined>(() => {
    if (!visibleItem) {
      return undefined;
    }

    return {
      ...certificate,
      certificateXref: visibleItem.certificateXref,
      userDomainCertId: visibleItem.userDomainCertId,
      domain: visibleItem.domain,
      caProvider: visibleItem.caProvider ?? certificate.caProvider,
      status: visibleItem.status,
      certType: visibleItem.certType,
      validFrom: visibleItem.validFrom ?? undefined,
      validTo: visibleItem.validTo ?? undefined,
      wildcard: visibleItem.wildcard,
      san: visibleItem.san,
      sanDomains: visibleItem.sanDomains ?? [],
      dnsConfigXref: visibleItem.dnsConfigXref ?? undefined,
      deploymentCredentialXrefs: visibleItem.deploymentCredentialXrefs ?? [],
      dnsCredentialKvPath: visibleItem.dnsCredentialKvPath ?? undefined,
      deploymentCredentialKvPaths:
        visibleItem.deploymentCredentialKvPaths ?? [],
      signatureAlgorithm: visibleItem.signatureAlgorithm,
      publicKeyAlgorithm: visibleItem.publicKeyAlgorithm,
      keySize: visibleItem.keySize,
      serialNumber: undefined,
      fingerprintSha256: undefined,
      userMessage: undefined,
      lastErrorAt: undefined,
    };
  }, [certificate, visibleItem]);

  return (
    <Dialog
      open={Boolean(item || visibleItem)}
      onOpenChange={(open) => {
        if (open) {
          return;
        }

        onClose();

        if (closeTimerRef.current) {
          window.clearTimeout(closeTimerRef.current);
        }

        closeTimerRef.current = window.setTimeout(() => {
          setVisibleItem(null);
          closeTimerRef.current = null;
        }, 240);
      }}
    >
      <DialogContent className="max-h-[85vh] overflow-y-auto overscroll-contain sm:max-w-4xl">
        {visibleItem && historyCertificate ? (
          <>
            <DialogHeader>
              <DialogTitle className="truncate">
                {visibleItem.domain}
              </DialogTitle>
              <DialogDescription>
                {visibleItem.certificateXref}
                {getRenewalTriggerLabel(visibleItem)
                  ? ` · ${getRenewalTriggerLabel(visibleItem)}`
                  : null}
              </DialogDescription>
              <Badge
                variant="outline"
                textOnly
                className={getHistoryStatusBadgeClass(visibleItem.status)}
              >
                {formatStatus(visibleItem.status)}
              </Badge>
            </DialogHeader>
            {canOpenDeployments ? (
              <Button
                variant="default"
                asChild
                className="ml-auto w-full md:w-fit"
              >
                <Link href={getHistoryDeploymentHref(visibleItem)}>
                  Deployments
                  <ArrowSquareOutIcon />
                </Link>
              </Button>
            ) : null}
            <CertDetailss certificate={historyCertificate} />
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
