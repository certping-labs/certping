// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";
import {
  CheckCircleIcon,
  CloudIcon,
  PackageIcon,
  HardDrivesIcon,
  WarningIcon,
  XCircleIcon,
} from "@phosphor-icons/react";
import { useRouter, useSearchParams } from "next/navigation";

import { DeployNewCertDialog } from "@/components/cert-manager/deploy-new-cert-dialog";
import { CertificateInventoryProgress } from "@/components/cert-manager/certificate-inventory-progress";
import { MetricCard, MetricStrip } from "@/components/common/metric-card";
import { Unauthorised } from "@/components/common/unautorised";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  deploymentSummaryMetrics,
  sortFailuresFirst,
} from "@/lib/cert-manager/deployment-summary";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/use-auth";
import { useAllUserDomainCertificateDeploymentSummaries } from "@/hooks/deployments";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import { canCreateDeployments, canViewDeployments } from "@/lib/authz";
import type { UserDomainCertificateDeploymentSummary } from "@/types/cert-manager";

const NUMERIC_COLUMN_CLASS = "text-right tabular-nums [&>button]:justify-end";

export default function CertificateDeploymentsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, isLoading: isLoadingAuth } = useAuth();
  const canView = canViewDeployments(user);
  const canCreate = canCreateDeployments(user);

  const [deployDialogOpen, setDeployDialogOpen] = useState(false);
  const [showFailedOnly, setShowFailedOnly] = useState(false);
  const [initialCertificateId, setInitialCertificateId] = useState<
    string | undefined
  >(undefined);

  const requestedDeployCertificateId =
    searchParams.get("deployCertificateXref") || undefined;
  const [initialSearch] = useState(
    () => searchParams.get("search")?.trim() ?? "",
  );
  const [viewMode, setViewMode] = useResponsiveViewMode({
    storageKey: "deployments_view",
  });

  useEffect(() => {
    if (!requestedDeployCertificateId) {
      return;
    }

    setInitialCertificateId(requestedDeployCertificateId);
    setDeployDialogOpen(true);

    const nextParams = new URLSearchParams(searchParams.toString());
    nextParams.delete("deployCertificateXref");
    const nextQuery = nextParams.toString();
    router.replace(
      nextQuery
        ? `/cert-manager/deployments?${nextQuery}`
        : "/cert-manager/deployments",
    );
  }, [requestedDeployCertificateId, router, searchParams]);

  const summaryQuery = useAllUserDomainCertificateDeploymentSummaries(
    undefined,
    { enabled: canView },
  );
  const summaries = useMemo(
    () => sortFailuresFirst(summaryQuery.data ?? []),
    [summaryQuery.data],
  );
  const metrics = useMemo(
    () => deploymentSummaryMetrics(summaries),
    [summaries],
  );

  const visibleSummaries = useMemo(
    () =>
      showFailedOnly
        ? summaries.filter((summary) => summary.deploymentsFailed > 0)
        : summaries,
    [showFailedOnly, summaries],
  );

  const openDomain = useCallback(
    (summary: UserDomainCertificateDeploymentSummary) =>
      router.push(
        `/cert-manager/deployments/${encodeURIComponent(String(summary.userDomainCertId))}`,
      ),
    [router],
  );

  const columns = useMemo<ColumnDef<UserDomainCertificateDeploymentSummary>[]>(
    () => [
      {
        accessorKey: "domain",
        header: "Domain",
        size: 240,
        cell: ({ row }) => (
          <div
            className="truncate font-medium text-foreground"
            title={row.original.domain}
          >
            {row.original.domain}
          </div>
        ),
      },
      {
        accessorKey: "deploymentsRequested",
        header: "Requests",
        enableSorting: true,
        meta: { className: NUMERIC_COLUMN_CLASS },
      },
      {
        accessorKey: "deploymentsSucceeded",
        header: "Succeeded",
        enableSorting: true,
        meta: { className: NUMERIC_COLUMN_CLASS },
        cell: ({ row }) => (
          <span className="status-success-text">
            {row.original.deploymentsSucceeded}
          </span>
        ),
      },
      {
        accessorKey: "deploymentsFailed",
        enableSorting: true,
        header: "Failed",
        meta: { className: NUMERIC_COLUMN_CLASS },
        cell: ({ row }) => (
          <span
            className={
              row.original.deploymentsFailed > 0
                ? "status-danger-text"
                : "text-muted-foreground"
            }
          >
            {row.original.deploymentsFailed}
          </span>
        ),
      },
      {
        id: "actions",
        enableHiding: false,
        header: () => <span className="sr-only">Actions</span>,
        cell: ({ row }) => (
          <div className="flex justify-end">
            <Button variant="subtle" size="sm" asChild>
              <Link
                href={`/cert-manager/deployments/${encodeURIComponent(
                  String(row.original.userDomainCertId),
                )}`}
              >
                View
              </Link>
            </Button>
          </div>
        ),
      },
    ],
    [],
  );

  if (isLoadingAuth || summaryQuery.isLoading) {
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
          isLoading={summaryQuery.isLoadingAdditionalPages}
          hasError={summaryQuery.isFetchNextPageError}
          loadedItems={summaryQuery.loadedItems}
          totalItems={summaryQuery.totalItems}
          inventoryLabel="deployment history"
          itemLabel="domains"
          onRetry={() => {
            void summaryQuery.retryAdditionalPages();
          }}
        />

        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-[-0.03em] text-foreground">
              Certificate deployments
            </h1>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-muted-foreground">
              Choose a domain to review its deployment history.
            </p>
          </div>
          {canCreate ? (
            <Button onClick={() => setDeployDialogOpen(true)}>
              <CloudIcon className="h-4 w-4" />
              Deploy certificate
            </Button>
          ) : null}
        </div>

        <MetricStrip aria-label="Deployment summary">
          <MetricCard
            icon={HardDrivesIcon}
            title="domains"
            value={metrics.domains}
          />
          <MetricCard
            icon={PackageIcon}
            title="deployments"
            value={metrics.totalRequests}
          />
          <MetricCard
            icon={CheckCircleIcon}
            title="healthy"
            value={metrics.healthyDomains}
            tone="success"
          />
          <MetricCard
            icon={XCircleIcon}
            title="need attention"
            value={metrics.domainsWithFailures}
            tone="danger"
          />
        </MetricStrip>

        {metrics.domainsWithFailures > 0 ? (
          <FailedDeploymentsCallout
            count={metrics.domainsWithFailures}
            showFailedOnly={showFailedOnly}
            onToggle={() => setShowFailedOnly((current) => !current)}
          />
        ) : null}

        {summaries.length === 0 ? (
          <Alert className="bg-card text-center">
            <AlertTitle className="font-bold">
              No deployment domains yet
            </AlertTitle>
            <AlertDescription>
              Domains with deployment history will appear here once certificates
              are pushed to saved targets.
            </AlertDescription>
          </Alert>
        ) : (
          <CustomTable
            viewSwitcher={{ value: viewMode, onValueChange: setViewMode }}
            renderGrid={(rows) => (
              <DeploymentsGrid summaries={rows} onOpenDomain={openDomain} />
            )}
            columns={columns}
            data={visibleSummaries}
            searchBy="domain"
            searchPlaceholder="Search deployment domains"
            defaultSearchTerm={initialSearch}
            showColumnVisibility={false}
            emptyTableMsg="No domains matched the current search."
            getRowId={(row) => row.userDomainCertId?.toString()}
            onRowClick={openDomain}
          />
        )}
      </div>

      <DeployNewCertDialog
        open={deployDialogOpen}
        onOpenChange={setDeployDialogOpen}
        initialCertificateId={initialCertificateId}
      />
    </>
  );
}

function FailedDeploymentsCallout({
  count,
  showFailedOnly,
  onToggle,
}: {
  count: number;
  showFailedOnly: boolean;
  onToggle: () => void;
}) {
  return (
    <Alert variant="warning">
      <WarningIcon aria-hidden />
      <AlertTitle>
        {count} {count === 1 ? "domain has" : "domains have"} failed deployments
      </AlertTitle>
      <AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          Open one to see which target rejected the certificate, then deploy it
          again.
        </span>
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-pressed={showFailedOnly}
          onClick={onToggle}
        >
          {showFailedOnly ? "Show all domains" : "Show failed"}
        </Button>
      </AlertDescription>
    </Alert>
  );
}

function DeploymentsGrid({
  summaries,
  onOpenDomain,
}: {
  summaries: UserDomainCertificateDeploymentSummary[];
  onOpenDomain: (summary: UserDomainCertificateDeploymentSummary) => void;
}) {
  if (summaries.length === 0) {
    return (
      <Alert className="bg-card">
        <AlertTitle>No domains matched</AlertTitle>
        <AlertDescription>
          Adjust the search term to find deployment history.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {summaries.map((summary) => {
        const hasFailures = summary.deploymentsFailed > 0;
        return (
          <button
            key={summary.userDomainCertId}
            type="button"
            onClick={() => onOpenDomain(summary)}
            className="rounded-xl border border-border bg-card p-4 text-left transition-colors hover:border-[hsl(var(--control-border-hover))] focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-foreground">
                  {summary.domain}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {summary.deploymentsRequested} deployment request
                  {summary.deploymentsRequested === 1 ? "" : "s"}
                </p>
              </div>
              <Badge variant={hasFailures ? "destructive" : "success"} textOnly>
                {hasFailures ? "Needs attention" : "Healthy"}
              </Badge>
            </div>

            <dl className="mt-4 grid grid-cols-3 gap-3 text-sm">
              <div>
                <dt className="text-xs text-muted-foreground">Requested</dt>
                <dd className="mt-1 font-semibold text-foreground tabular-nums">
                  {summary.deploymentsRequested}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Succeeded</dt>
                <dd className="mt-1 font-semibold status-success-text tabular-nums">
                  {summary.deploymentsSucceeded}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Failed</dt>
                <dd
                  className={
                    hasFailures
                      ? "mt-1 font-semibold status-danger-text tabular-nums"
                      : "mt-1 font-semibold text-muted-foreground tabular-nums"
                  }
                >
                  {summary.deploymentsFailed}
                </dd>
              </div>
            </dl>
          </button>
        );
      })}
    </div>
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
