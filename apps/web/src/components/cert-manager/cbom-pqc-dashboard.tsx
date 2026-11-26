// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { WarningIcon, ArrowsClockwiseIcon } from "@phosphor-icons/react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import {
  cbomPqcDashboardKeys,
  usePqcReadinessCertificates,
  usePqcReadinessReport,
} from "@/hooks/use-cbom-pqc-dashboard";
import type { QuantumStatus } from "@/types/cbom-pqc";
import { AlgorithmTimeline } from "./pqc-dashboard/algorithm-timeline";
import { CbomExport } from "./pqc-dashboard/cbom-export";
import {
  CertificateInventory,
  INVENTORY_PAGE_SIZES,
} from "./pqc-dashboard/certificate-inventory";
import { DashboardDataAlert } from "./pqc-dashboard/dashboard-data-alert";
import { buildAlgorithmGroups } from "./pqc-dashboard/pqc-dashboard-model";
import { PqcSummaryCards } from "./pqc-dashboard/pqc-summary-cards";
import { ReadinessSidebar } from "./pqc-dashboard/readiness-sidebar";
import { TopActionsCard } from "./pqc-dashboard/top-actions-card";

const EMPTY_ALGORITHMS = [] as const;

export function CbomPqcDashboard() {
  const queryClient = useQueryClient();
  const pqcQuery = usePqcReadinessReport();
  const [inventoryFilter, setInventoryFilter] = useState<QuantumStatus | "ALL">(
    "ALL",
  );
  const [inventoryPage, setInventoryPage] = useState(0);
  const [inventoryPageSize, setInventoryPageSize] = useState<number>(
    INVENTORY_PAGE_SIZES[0],
  );
  const inventoryQuery = usePqcReadinessCertificates({
    ...(inventoryFilter === "ALL" ? {} : { quantumStatus: inventoryFilter }),
    page: inventoryPage,
    size: inventoryPageSize,
  });
  const algorithms = pqcQuery.data?.algorithms ?? EMPTY_ALGORITHMS;
  const algorithmGroups = useMemo(
    () => buildAlgorithmGroups(algorithms),
    [algorithms],
  );
  const refreshDashboard = () => {
    void queryClient.invalidateQueries({
      queryKey: cbomPqcDashboardKeys.pqcReadiness,
    });
  };

  const changeInventoryFilter = (filter: QuantumStatus | "ALL") => {
    setInventoryFilter(filter);
    setInventoryPage(0);
  };

  const changeInventoryPageSize = (size: number) => {
    setInventoryPageSize(size);
    setInventoryPage(0);
  };

  const reviewStatus = (status: QuantumStatus) => {
    changeInventoryFilter(status);
    window.requestAnimationFrame(() => {
      document
        .getElementById("certificate-inventory")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  return (
    <main className="space-y-5 p-4 sm:p-6">
      <PageHeader
        title="PQC readiness"
        subtitle="Post-quantum cryptography posture, NIST transition milestones, and certificate-level remediation priorities."
        actions={
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={refreshDashboard}
            disabled={pqcQuery.isFetching || inventoryQuery.isFetching}
          >
            <ArrowsClockwiseIcon
              aria-hidden="true"
              className={
                pqcQuery.isFetching || inventoryQuery.isFetching
                  ? "animate-spin"
                  : ""
              }
            />
            Refresh
          </Button>
        }
      />

      <DashboardDataAlert
        isPqcReadinessError={pqcQuery.isError || inventoryQuery.isError}
      />

      <PqcSummaryCards
        summary={pqcQuery.data?.summary}
        isLoading={pqcQuery.isLoading}
      />

      <section className="grid min-w-0 items-start gap-3 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-4">
          <AlgorithmTimeline
            groups={algorithmGroups}
            isLoading={pqcQuery.isLoading}
          />

          {(pqcQuery.data?.summary.disallowed2035 ?? 0) > 0 ? (
            <MigrationAlert
              count={pqcQuery.data?.summary.disallowed2035 ?? 0}
              onReview={() => reviewStatus("DISALLOWED_2035")}
            />
          ) : null}

          <CbomExport
            totalCertificates={pqcQuery.data?.summary.totalCertificates}
            isLoading={pqcQuery.isLoading}
          />
        </div>
        <ReadinessSidebar summary={pqcQuery.data?.summary} />
      </section>

      <TopActionsCard
        summary={pqcQuery.data?.summary}
        onReviewStatus={reviewStatus}
      />

      <CertificateInventory
        page={inventoryQuery.data}
        pageSize={inventoryPageSize}
        filter={inventoryFilter}
        isLoading={inventoryQuery.isPending}
        isFetching={inventoryQuery.isFetching}
        onFilterChange={changeInventoryFilter}
        onPageChange={setInventoryPage}
        onPageSizeChange={changeInventoryPageSize}
      />
    </main>
  );
}

function MigrationAlert({
  count,
  onReview,
}: {
  count: number;
  onReview: () => void;
}) {
  return (
    <Alert
      variant="destructive"
      className="border-danger-border bg-danger-soft text-foreground"
    >
      <WarningIcon aria-hidden="true" className="size-4" />
      <AlertTitle>Migration planning required</AlertTitle>
      <AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          {count.toLocaleString()} certificates use algorithms the readiness API
          marks for disallowance by 2035.
        </span>
        <Button type="button" size="sm" variant="outline" onClick={onReview}>
          Review affected certificates
        </Button>
      </AlertDescription>
    </Alert>
  );
}
