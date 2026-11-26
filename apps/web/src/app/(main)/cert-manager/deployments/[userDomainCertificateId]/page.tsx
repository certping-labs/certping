// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Image from "next/image";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";
import {
  ArrowLeftIcon,
  CheckCircleIcon,
  CloudIcon,
  PackageIcon,
  WarningIcon,
  XCircleIcon,
} from "@phosphor-icons/react";
import {
  useParams,
  usePathname,
  useRouter,
  useSearchParams,
} from "next/navigation";

import { DeployNewCertDialog } from "@/components/cert-manager/deploy-new-cert-dialog";
import { CertificateInventoryProgress } from "@/components/cert-manager/certificate-inventory-progress";
import { CredentialReferenceTrigger } from "@/components/cert-manager/credential-reference-trigger";
import { MetricCard, MetricStrip } from "@/components/common/metric-card";
import { Unauthorised } from "@/components/common/unautorised";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/use-auth";
import { useAllDeployments } from "@/hooks/deployments";
import { canCreateDeployments, canViewDeployments } from "@/lib/authz";
import {
  DEPLOYMENT_FLOW_OPTIONS,
  formatDeploymentFlowType,
} from "@/lib/deployment-flow";
import {
  buildDeploymentRequestHref,
  computeDeploymentMetrics,
  filterDeploymentsByStatusGroup,
  formatDeploymentStatusLabel,
  getDeploymentStatusBadgeClass,
  parsePositiveInteger,
} from "@/lib/cert-manager/deployments-history-page-helpers";
import { getProviderPresentation } from "@/lib/credential-providers";
import { compareDateValues } from "@/lib/table-sorting";
import { formatDateTimeCompact } from "@/lib/utils";
import type {
  DeploymentQueryFilters,
  DeploymentRecord,
} from "@/types/cert-manager";

export default function UserDomainCertificateDeploymentsPage() {
  const params = useParams<{ userDomainCertificateId: string }>();
  const userDomainCertificateId = Array.isArray(params?.userDomainCertificateId)
    ? params.userDomainCertificateId[0] || ""
    : params?.userDomainCertificateId || "";
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { user, isLoading: isLoadingAuth } = useAuth();
  const canView = canViewDeployments(user);
  const canCreate = canCreateDeployments(user);

  const [deployDialogOpen, setDeployDialogOpen] = useState(false);
  const [initialCertificateId, setInitialCertificateId] = useState<
    string | undefined
  >(undefined);

  const requestedDeployCertificateId =
    searchParams.get("deployCertificateXref") || undefined;
  const selectedDomain =
    searchParams.get("domain")?.trim() || "Deployment history";
  const tableStatusFilter = searchParams.get("status")?.trim() ?? "";
  const tableFlowTypeFilter = searchParams.get("flowType")?.trim() ?? "";
  const tableTargetTypeFilter = searchParams.get("targetType")?.trim() ?? "";
  const statusGroup =
    searchParams.get("statusGroup")?.trim().toLowerCase() ?? "";

  const defaultTableFilters = useMemo(
    () => ({
      ...(tableStatusFilter ? { status: tableStatusFilter } : {}),
      ...(tableFlowTypeFilter ? { flowType: tableFlowTypeFilter } : {}),
      ...(tableTargetTypeFilter ? { targetType: tableTargetTypeFilter } : {}),
    }),
    [tableFlowTypeFilter, tableStatusFilter, tableTargetTypeFilter],
  );
  const [initialTableSearchTerm] = useState(
    () => searchParams.get("search")?.trim() ?? "",
  );
  const [tableFilterState, setTableFilterState] =
    useState<Record<string, string>>(defaultTableFilters);

  useEffect(() => {
    setTableFilterState(defaultTableFilters);
  }, [defaultTableFilters]);

  useEffect(() => {
    const nextParams = new URLSearchParams(searchParams.toString());
    ["search", "status", "flowType", "targetType"].forEach((key) =>
      nextParams.delete(key),
    );

    if (tableFilterState.status) {
      nextParams.set("status", tableFilterState.status);
    }
    if (tableFilterState.flowType) {
      nextParams.set("flowType", tableFilterState.flowType);
    }
    if (tableFilterState.targetType) {
      nextParams.set("targetType", tableFilterState.targetType);
    }

    const nextQuery = nextParams.toString();
    if (searchParams.toString() !== nextQuery) {
      router.replace(nextQuery ? `${pathname}?${nextQuery}` : pathname, {
        scroll: false,
      });
    }
  }, [pathname, router, searchParams, tableFilterState]);

  useEffect(() => {
    if (!requestedDeployCertificateId) {
      return;
    }

    setInitialCertificateId(requestedDeployCertificateId);
    setDeployDialogOpen(true);

    const nextParams = new URLSearchParams(searchParams.toString());
    nextParams.delete("deployCertificateXref");
    const nextQuery = nextParams.toString();
    router.replace(nextQuery ? `${pathname}?${nextQuery}` : pathname);
  }, [pathname, requestedDeployCertificateId, router, searchParams]);

  const deploymentFilters = useMemo<DeploymentQueryFilters>(
    () => ({
      userDomainCertificateId,
      status: searchParams.get("status") || undefined,
      targetType: searchParams.get("targetType") || undefined,
      flowType: searchParams.get("flowType") || undefined,
      from: searchParams.get("from") || undefined,
      to: searchParams.get("to") || undefined,
      certificateXref: searchParams.get("certificateXref") || undefined,
      requestId: searchParams.get("requestId") || undefined,
      view: "list",
      sort: searchParams.get("sort") || undefined,
      size: parsePositiveInteger(searchParams.get("size")),
    }),
    [searchParams, userDomainCertificateId],
  );

  const deploymentsQuery = useAllDeployments(deploymentFilters);
  const hasServerFilters = Boolean(
    deploymentFilters.status ||
    deploymentFilters.flowType ||
    deploymentFilters.targetType ||
    deploymentFilters.from ||
    deploymentFilters.to ||
    deploymentFilters.certificateXref ||
    deploymentFilters.requestId,
  );
  const deploymentOptionSourceQuery = useAllDeployments(
    { userDomainCertificateId, view: "list" },
    {
      enabled: hasServerFilters && deploymentsQuery.isInventoryComplete,
    },
  );

  const deployments = useMemo(() => {
    return filterDeploymentsByStatusGroup(
      deploymentsQuery.data || [],
      statusGroup,
    );
  }, [deploymentsQuery.data, statusGroup]);

  const allDeployments = useMemo(
    () =>
      hasServerFilters
        ? deploymentOptionSourceQuery.data || []
        : deploymentsQuery.data || [],
    [deploymentOptionSourceQuery.data, deploymentsQuery.data, hasServerFilters],
  );

  const targetTypeOptions = useMemo(
    () =>
      Array.from(
        new Set(
          allDeployments
            .map((deployment) => deployment.targetType)
            .filter((value): value is string => Boolean(value)),
        ),
      ).sort((left, right) => left.localeCompare(right)),
    [allDeployments],
  );

  const metrics = useMemo(
    () => computeDeploymentMetrics(deployments),
    [deployments],
  );

  const columns = useMemo<ColumnDef<DeploymentRecord>[]>(
    () => [
      {
        accessorKey: "domain",
        header: "Domain",
        size: 240,
        cell: ({ row }) => (
          <div
            className="truncate font-medium"
            title={row.original.domain || undefined}
          >
            {row.original.domain || "Domain unavailable"}
          </div>
        ),
      },
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
              {formatDeploymentStatusLabel(row.original.status)}
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
            <div className="flex items-start gap-2">
              {presentation.logo ? (
                <Image
                  src={presentation.logo}
                  alt=""
                  width={16}
                  height={16}
                  className="mt-1 h-4 w-4 shrink-0 object-contain"
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
          formatDateTimeCompact(
            row.original.requestedAt || row.original.createdAt || null,
          ),
      },
      {
        accessorKey: "completedAt",
        header: "Completed",
        enableSorting: true,
        sortingFn: (rowA, rowB, columnId) =>
          compareDateValues(rowA.getValue(columnId), rowB.getValue(columnId)),
        cell: ({ row }) =>
          formatDateTimeCompact(row.original.completedAt || null),
      },
      {
        accessorKey: "deploymentCredentialXref",
        header: "Credential",
        cell: ({ row }) => {
          const credentialId = row.original.deploymentCredentialXref;
          return credentialId ? (
            <CredentialReferenceTrigger credentialXref={credentialId}>
              {credentialId}
            </CredentialReferenceTrigger>
          ) : (
            "-"
          );
        },
      },
      {
        id: "actions",
        enableHiding: false,
        header: () => <div className="text-right">Actions</div>,
        cell: ({ row }) => (
          <div className="flex justify-end">
            {row.original.requestId ? (
              <Button variant="subtle" size="sm" asChild>
                <Link
                  href={buildDeploymentRequestHref(
                    userDomainCertificateId,
                    row.original.requestId,
                  )}
                  onClick={(event) => event.stopPropagation()}
                >
                  View
                </Link>
              </Button>
            ) : (
              "-"
            )}
          </div>
        ),
      },
    ],
    [userDomainCertificateId],
  );

  const isInitialLoading =
    isLoadingAuth ||
    (deploymentsQuery.isLoading && !deploymentsQuery.data) ||
    (hasServerFilters &&
      deploymentOptionSourceQuery.isLoading &&
      !deploymentOptionSourceQuery.data);

  if (isInitialLoading) {
    return <DeploymentsSkeleton />;
  }

  if (!canView) {
    return (
      <div className="p-6">
        <Unauthorised />
      </div>
    );
  }

  return (
    <>
      <div className="space-y-4 p-6">
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

        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div className="mb-3">
              <Button variant="outline" size="sm" asChild>
                <Link href="/cert-manager/deployments">
                  <ArrowLeftIcon className="h-4 w-4" />
                  Back
                </Link>
              </Button>
            </div>
            <h1 className="text-2xl font-semibold tracking-[-0.03em] text-foreground">
              {selectedDomain}
            </h1>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-muted-foreground">
              Deployment history for this certificate domain.
            </p>
          </div>
          {canCreate ? (
            <Button onClick={() => setDeployDialogOpen(true)}>
              <CloudIcon className="h-4 w-4" />
              Deploy certificate
            </Button>
          ) : null}
        </div>

        <MetricStrip>
          <MetricCard
            icon={PackageIcon}
            title="deployments"
            value={metrics.total}
            description="Deployment attempts"
            tone="primary"
          />
          <MetricCard
            icon={CheckCircleIcon}
            title="succeeded"
            value={metrics.success}
            description="Completed successfully"
            tone="success"
          />
          <MetricCard
            icon={WarningIcon}
            title="pending"
            value={metrics.pending}
            description="Still processing"
            tone="warning"
          />
          <MetricCard
            icon={XCircleIcon}
            title="failed"
            value={metrics.failed}
            description="Needs attention"
            tone="danger"
          />
        </MetricStrip>

        <div className="space-y-3">
          {deploymentsQuery.isFetching ? (
            <div className="text-xs text-muted-foreground">
              Updating deployment results...
            </div>
          ) : null}
          <CustomTable
            columns={columns}
            data={deployments}
            searchBy={[
              "domain",
              "certificateXref",
              "requestId",
              "status",
              "targetType",
              "flowType",
              "deploymentCredentialXref",
              "source",
            ]}
            searchPlaceholder="Search domains, certificate refs, request IDs, status, targets, or credentials"
            filters={[
              {
                id: "status",
                type: "select",
                label: "Status",
                placeholder: "Deployment status",
                options: [
                  { label: "All statuses", value: "all" },
                  { label: "Pending", value: "PENDING" },
                  { label: "In progress", value: "IN_PROGRESS" },
                  { label: "Completed", value: "COMPLETED" },
                  { label: "Success", value: "SUCCESS" },
                  { label: "Failed", value: "FAILED" },
                ],
              },
              {
                id: "flowType",
                type: "select",
                label: "Flow",
                placeholder: "Deployment flow",
                options: [
                  { label: "All flows", value: "all" },
                  ...DEPLOYMENT_FLOW_OPTIONS,
                ],
              },
              {
                id: "targetType",
                type: "select",
                label: "Target",
                placeholder: "Deployment target",
                options: [
                  { label: "All targets", value: "all" },
                  ...targetTypeOptions.map((targetType) => ({
                    label: getProviderPresentation(targetType).label,
                    value: targetType,
                  })),
                ],
              },
            ]}
            defaultFilterValues={defaultTableFilters}
            defaultSearchTerm={initialTableSearchTerm}
            onFilterValuesChange={setTableFilterState}
            emptyTableMsg="No deployments found for the current filters."
            getRowId={(row) => String(row.id)}
            showColumnVisibility
            tableClassName="overflow-x-auto"
            onRowClick={(row) => {
              if (row.requestId) {
                router.push(
                  buildDeploymentRequestHref(
                    userDomainCertificateId,
                    row.requestId,
                  ),
                );
              }
            }}
          />
        </div>
      </div>

      <DeployNewCertDialog
        open={deployDialogOpen}
        onOpenChange={setDeployDialogOpen}
        initialCertificateId={initialCertificateId}
      />
    </>
  );
}

function DeploymentsSkeleton() {
  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-8 w-72" />
          <Skeleton className="h-4 w-80" />
        </div>
        <Skeleton className="h-10 w-40" />
      </div>
      <div className="grid gap-4 md:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-96" />
    </div>
  );
}
