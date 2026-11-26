// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import Image from "next/image";
import { useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";
import {
  CloudIcon,
  ArrowSquareOutIcon,
  MagnifyingGlassIcon,
} from "@phosphor-icons/react";

import { useAllDeployments } from "@/hooks/deployments";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import { formatDeploymentFlowType } from "@/lib/deployment-flow";
import { getProviderPresentation } from "@/lib/credential-providers";
import { fuzzySearch } from "@/lib/fuzzy-search";
import { compareDateValues } from "@/lib/table-sorting";
import { formatDateTime } from "@/lib/utils";
import type { DeploymentRecord } from "@/types/cert-manager";
import type { SSLCertificateDetails } from "@/types/ssl";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ViewSwitcher } from "@/components/ui/view-switcher";
import { CredentialReferenceTrigger } from "@/components/cert-manager/credential-reference-trigger";
import { CertificateInventoryProgress } from "@/components/cert-manager/certificate-inventory-progress";
import { getCertificateStatusLabel } from "@/lib/cert-manager/certificate-status";

const DEPLOYMENT_SEARCH_KEYS = [
  "requestId",
  "status",
  "targetType",
  "flowType",
  "deploymentCredentialXref",
  "domain",
];

const formatStatus = (value: string) =>
  value
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());

const getDeploymentStatusBadgeClass = (status: string) => {
  switch (status.toUpperCase()) {
    case "SUCCESS":
      return "status-success-text";
    case "FAILED":
    case "FAILED_VALIDATION":
    case "FAILED_DEPLOYMENT":
    case "PUBLISH_FAILED":
      return "status-danger-text";
    case "PENDING":
    case "IN_PROGRESS":
    case "DEPLOYING":
      return "status-warning-text";
    default:
      return "text-muted-foreground";
  }
};

export function CertDeployments({
  certificate,
  canDeploy,
  canDeployCurrentCert,
  onDeploy,
  selectedCertificateXref,
  selectedCertificateStatus,
  onResetSelection,
}: {
  certificate: SSLCertificateDetails;
  canDeploy: boolean;
  canDeployCurrentCert: boolean;
  onDeploy: () => void;
  selectedCertificateXref?: string;
  selectedCertificateStatus?: string;
  onResetSelection?: () => void;
}) {
  const router = useRouter();
  const effectiveCertificateXref =
    selectedCertificateXref || certificate.certificateXref;
  const deploymentsQuery = useAllDeployments({
    certificateXref: effectiveCertificateXref,
    view: "list",
  });

  const deployments = useMemo(
    () => deploymentsQuery.data || [],
    [deploymentsQuery.data],
  );
  const [viewMode, setViewMode] = useResponsiveViewMode({
    storageKey: "cert-deployments-history_view",
  });
  const [cardSearchTerm, setCardSearchTerm] = useState("");
  const cardDeployments = useMemo(() => {
    const term = cardSearchTerm.trim();
    if (!term) {
      return deployments;
    }
    return fuzzySearch(term, deployments, DEPLOYMENT_SEARCH_KEYS);
  }, [cardSearchTerm, deployments]);
  const goToDeployment = useMemo(
    () => (record: DeploymentRecord) => {
      if (record.requestId && record.userDomainCertId != null) {
        router.push(
          `/cert-manager/deployments/${encodeURIComponent(
            String(record.userDomainCertId),
          )}/${encodeURIComponent(record.requestId)}`,
        );
      }
    },
    [router],
  );
  const isViewingHistoricalCertificate = Boolean(
    effectiveCertificateXref &&
    certificate.certificateXref &&
    effectiveCertificateXref !== certificate.certificateXref,
  );
  const openDeploymentsHref = useMemo(() => {
    if (!certificate.userDomainCertId) {
      return "/cert-manager/deployments";
    }

    const params = new URLSearchParams();
    params.set("domain", certificate.domain);
    if (effectiveCertificateXref) {
      params.set("certificateXref", effectiveCertificateXref);
    }

    const query = params.toString();
    return query
      ? `/cert-manager/deployments/${encodeURIComponent(
          certificate.userDomainCertId,
        )}?${query}`
      : `/cert-manager/deployments/${encodeURIComponent(
          certificate.userDomainCertId,
        )}`;
  }, [
    certificate.domain,
    certificate.userDomainCertId,
    effectiveCertificateXref,
  ]);
  const columns = useMemo<ColumnDef<DeploymentRecord>[]>(
    () => [
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => (
          <div className="flex justify-start">
            <Badge
              variant="outline"
              textOnly
              className={getDeploymentStatusBadgeClass(row.original.status)}
            >
              {formatStatus(row.original.status)}
            </Badge>
          </div>
        ),
      },
      {
        accessorKey: "targetType",
        header: "Target",
        cell: ({ row }) => {
          const presentation = getProviderPresentation(row.original.targetType);
          return (
            <div className="flex items-center gap-2">
              {presentation.logo ? (
                <Image
                  src={presentation.logo}
                  alt=""
                  width={18}
                  height={18}
                  className="h-4.5 w-4.5 shrink-0 object-contain"
                />
              ) : null}
              <span>{presentation.label}</span>
            </div>
          );
        },
      },
      {
        accessorKey: "flowType",
        header: "Flow",
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatDeploymentFlowType(row.original.flowType)}
          </span>
        ),
      },
      {
        accessorKey: "requestedAt",
        header: "Requested",
        enableSorting: true,
        sortingFn: (rowA, rowB) =>
          compareDateValues(
            rowA.original.requestedAt || rowA.original.createdAt,
            rowB.original.requestedAt || rowB.original.createdAt,
          ),
        cell: ({ row }) =>
          formatDateTime(
            row.original.requestedAt || row.original.createdAt || null,
          ),
      },
      {
        accessorKey: "deploymentCredentialXref",
        header: "Credential",
        cell: ({ row }) =>
          row.original.deploymentCredentialXref ? (
            <CredentialReferenceTrigger
              credentialXref={row.original.deploymentCredentialXref}
            >
              {row.original.deploymentCredentialXref}
            </CredentialReferenceTrigger>
          ) : (
            "-"
          ),
      },
      {
        id: "actions",
        header: () => <div className="text-right">Actions</div>,
        cell: ({ row }) => (
          <div className="flex justify-end">
            {row.original.requestId && row.original.userDomainCertId != null ? (
              <Button variant="outline" size="sm" asChild>
                <Link
                  href={`/cert-manager/deployments/${encodeURIComponent(
                    String(row.original.userDomainCertId),
                  )}/${encodeURIComponent(row.original.requestId)}`}
                  onClick={(e) => e.stopPropagation()}
                >
                  View details
                </Link>
              </Button>
            ) : (
              "-"
            )}
          </div>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <div className="flex w-full flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="">
          <h3 className="text-xl font-semibold">
            Latest Certificate Deployment history
          </h3>
          <p className="text-sm text-muted-foreground">
            {isViewingHistoricalCertificate
              ? "Deployment records for the selected certificate version."
              : "Deployment records for the latest certificate."}
          </p>
          {isViewingHistoricalCertificate ? (
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="outline" textOnly>
                Historical certificate
              </Badge>
              <span className="font-mono">{effectiveCertificateXref}</span>
              {selectedCertificateStatus ? (
                <Badge variant="outline" textOnly>
                  {getCertificateStatusLabel(selectedCertificateStatus)}
                </Badge>
              ) : null}
            </div>
          ) : null}
        </div>
        <div className="flex flex-wrap gap-2 md:justify-end">
          {canDeployCurrentCert &&
          certificate.certificateXref &&
          !isViewingHistoricalCertificate ? (
            <Button onClick={onDeploy}>
              <CloudIcon className="size-4 w-full md:w-fit" />
              Deploy certificate
            </Button>
          ) : null}
          {isViewingHistoricalCertificate && onResetSelection ? (
            <Button variant="outline" onClick={onResetSelection}>
              Back to current certificate
            </Button>
          ) : null}
          <Button variant="outline" asChild>
            <Link href={openDeploymentsHref}>
              <ArrowSquareOutIcon className="size-4 w-full md:w-fit" />
              All Deployments History
            </Link>
          </Button>
        </div>
      </div>

      {!canDeploy ? (
        <Alert>
          <AlertTitle>Deployment access is restricted</AlertTitle>
          <AlertDescription>
            You can view deployment history, but deployment actions are not
            available for this role.
          </AlertDescription>
        </Alert>
      ) : null}

      <CertificateInventoryProgress
        isLoading={deploymentsQuery.isLoadingAdditionalPages}
        hasError={deploymentsQuery.isFetchNextPageError}
        loadedItems={deploymentsQuery.loadedItems}
        totalItems={deploymentsQuery.totalItems}
        inventoryLabel="deployment history"
        itemLabel="deployments"
        onRetry={() => {
          void deploymentsQuery.retryAdditionalPages();
        }}
      />

      {deploymentsQuery.isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : deployments.length === 0 ? (
        <Alert className="bg-card">
          <AlertTitle>No deployments for this certificate</AlertTitle>
          <AlertDescription>
            {isViewingHistoricalCertificate
              ? "No deployment records were found for the selected certificate version."
              : "No deployment records were found for this certificate."}
          </AlertDescription>
        </Alert>
      ) : (
        <div className="space-y-4">
          {viewMode === "table" ? (
            <CustomTable
              viewSwitcher={{ value: viewMode, onValueChange: setViewMode }}
              columns={columns}
              data={deployments}
              emptyTableMsg="No deployment records available for this certificate."
              getRowId={(row) => String(row.id)}
              pageSize={6}
              searchBy={DEPLOYMENT_SEARCH_KEYS}
              searchPlaceholder="Search request IDs, status, target, credential, or domain"
              onRowClick={goToDeployment}
            />
          ) : (
            <>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="relative flex-1 sm:max-w-sm">
                  <MagnifyingGlassIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={cardSearchTerm}
                    onChange={(event) => setCardSearchTerm(event.target.value)}
                    placeholder="Search request IDs, status, target, or credential"
                    className="pr-3 pl-9"
                    aria-label="Search deployment history"
                  />
                </div>
                <ViewSwitcher
                  value={viewMode}
                  onValueChange={setViewMode}
                  showLabels={false}
                />
              </div>
              <DeploymentHistoryGrid
                deployments={cardDeployments}
                onOpenDeployment={goToDeployment}
              />
            </>
          )}
        </div>
      )}
    </div>
  );
}

function DeploymentHistoryGrid({
  deployments,
  onOpenDeployment,
}: {
  deployments: DeploymentRecord[];
  onOpenDeployment: (record: DeploymentRecord) => void;
}) {
  if (deployments.length === 0) {
    return (
      <Alert className="bg-card">
        <AlertTitle>No deployments matched</AlertTitle>
        <AlertDescription>
          Adjust the search term to find deployment records.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4">
      {deployments.map((record) => {
        const presentation = getProviderPresentation(record.targetType);
        const canOpen =
          Boolean(record.requestId) && record.userDomainCertId != null;
        return (
          <div
            key={record.id}
            className="min-w-0 space-y-4 rounded-lg border border-border bg-card p-4"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2">
                {presentation.logo ? (
                  <Image
                    src={presentation.logo}
                    alt=""
                    width={18}
                    height={18}
                    className="h-4.5 w-4.5 shrink-0 object-contain"
                  />
                ) : null}
                <span className="truncate text-sm font-semibold text-foreground">
                  {presentation.label}
                </span>
              </div>
              <Badge
                variant="outline"
                textOnly
                className={getDeploymentStatusBadgeClass(record.status)}
              >
                {formatStatus(record.status)}
              </Badge>
            </div>

            <dl className="grid grid-cols-2 gap-3 text-sm">
              <div className="min-w-0">
                <dt className="text-xs text-muted-foreground">Flow</dt>
                <dd className="mt-1 truncate text-foreground">
                  {formatDeploymentFlowType(record.flowType)}
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs text-muted-foreground">Requested</dt>
                <dd className="mt-1 truncate text-foreground">
                  {formatDateTime(
                    record.requestedAt || record.createdAt || null,
                  )}
                </dd>
              </div>
              <div className="col-span-2 min-w-0">
                <dt className="text-xs text-muted-foreground">Credential</dt>
                <dd className="mt-1 truncate">
                  {record.deploymentCredentialXref ? (
                    <CredentialReferenceTrigger
                      credentialXref={record.deploymentCredentialXref}
                    >
                      {record.deploymentCredentialXref}
                    </CredentialReferenceTrigger>
                  ) : (
                    "-"
                  )}
                </dd>
              </div>
            </dl>

            {canOpen ? (
              <Button
                variant="outline"
                size="sm"
                className="w-full"
                onClick={() => onOpenDeployment(record)}
              >
                View details
              </Button>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
