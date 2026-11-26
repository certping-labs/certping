// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React, { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CustomTable } from "@/components/ui/custom-table";
import type { PqcReadinessCertificate, QuantumStatus } from "@/types/cbom-pqc";
import type { SpringPage } from "@/types/pagination";
import { CertificateDetailsDialog } from "./certificate-details-dialog";
import { PQC_STATUS_COPY } from "./pqc-status";

export const INVENTORY_PAGE_SIZES = [15, 30, 50, 100] as const;

const EMPTY_PAGE: readonly PqcReadinessCertificate[] = [];

interface CertificateInventoryProps {
  page: SpringPage<PqcReadinessCertificate> | undefined;
  pageSize: number;
  filter: QuantumStatus | "ALL";
  isLoading: boolean;
  isFetching: boolean;
  onFilterChange: (filter: QuantumStatus | "ALL") => void;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
}

export function CertificateInventory({
  page,
  pageSize,
  filter,
  isLoading,
  isFetching,
  onFilterChange,
  onPageChange,
  onPageSizeChange,
}: CertificateInventoryProps) {
  const [selectedCertificate, setSelectedCertificate] =
    useState<PqcReadinessCertificate | null>(null);
  const columns = useMemo<ColumnDef<PqcReadinessCertificate>[]>(
    () => [
      {
        accessorKey: "commonName",
        header: "Certificate",
        cell: ({ row }) => (
          <div>
            <p className="font-medium">
              {row.original.commonName || "Unknown name"}
            </p>
            <p className="font-mono text-xs text-muted-foreground">
              {row.original.source === "DISCOVERED" ? "Discovered: " : ""}
              {row.original.certificateXref}
            </p>
          </div>
        ),
      },
      {
        accessorKey: "keyAlgorithm",
        header: "Public key",
        cell: ({ row }) => (
          <div>
            <p>{row.original.keyAlgorithm || "Unknown"}</p>
            <p className="text-xs text-muted-foreground">
              {row.original.keySize
                ? `${row.original.keySize}-bit`
                : row.original.curve || "Metadata unavailable"}
            </p>
          </div>
        ),
      },
      {
        accessorKey: "quantumStatus",
        header: "Transition status",
        cell: ({ row }) => (
          <Badge
            variant={PQC_STATUS_COPY[row.original.quantumStatus].variant}
            includeDot
          >
            {PQC_STATUS_COPY[row.original.quantumStatus].label}
          </Badge>
        ),
      },
      {
        accessorKey: "hndlRisk",
        header: "HNDL risk",
        cell: ({ row }) => (
          <Badge
            variant={
              row.original.hndlRisk === "HIGH" ? "destructive" : "secondary"
            }
          >
            {row.original.hndlRisk}
          </Badge>
        ),
      },
      {
        id: "actions",
        header: "",
        cell: ({ row }) => (
          <div className="text-right">
            <Button
              type="button"
              size="sm"
              variant="secondary"
              onClick={() => setSelectedCertificate(row.original)}
            >
              View details
            </Button>
          </div>
        ),
      },
    ],
    [],
  );

  return (
    <section
      id="certificate-inventory"
      className="scroll-mt-6 space-y-3"
      aria-labelledby="inventory-heading"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="inventory-heading" className="text-base font-semibold">
            Certificate inventory
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Review the certificates behind each readiness signal.
          </p>
        </div>
        {filter !== "ALL" ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => onFilterChange("ALL")}
          >
            Clear filter
          </Button>
        ) : null}
      </div>
      <CustomTable
        columns={columns}
        data={page?.content ?? (EMPTY_PAGE as PqcReadinessCertificate[])}
        isLoading={isLoading}
        emptyTableMsg={
          filter === "ALL"
            ? "No certificates in this report yet."
            : `No certificates match ${PQC_STATUS_COPY[filter].label}.`
        }
        showColumnVisibility={false}
        pageSize={pageSize}
        serverPagination={{
          page: page?.number ?? 0,
          totalPages: page?.totalPages ?? 0,
          pageSize,
          totalElements: page?.totalElements ?? 0,
          pageSizeOptions: INVENTORY_PAGE_SIZES,
          disabled: isFetching,
          onPageChange,
          onPageSizeChange,
        }}
        getRowId={(row) => row.certificateXref}
        denseRows
        tableHeaderClassName="[&_th]:h-9 [&_th]:text-[11px] [&_th]:font-semibold [&_th]:uppercase [&_th]:tracking-wide"
      />
      <CertificateDetailsDialog
        certificate={selectedCertificate}
        onOpenChange={(open) => {
          if (!open) setSelectedCertificate(null);
        }}
      />
    </section>
  );
}
