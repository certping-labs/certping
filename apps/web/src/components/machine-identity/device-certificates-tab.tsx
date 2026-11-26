// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";

import {
  CERTIFICATE_COLUMNS,
  CERTIFICATE_DEFAULT_HIDDEN_COLUMNS,
} from "@/components/machine-identity/certificate-columns";
import { PaginatedTableCard } from "@/components/machine-identity/paginated-table-card";
import { useDeviceCertificates } from "@/hooks/machine-identity/use-machine-certificates";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";

/** A device's certificates, reusing the same columns as the module-wide certificate list. */
export function DeviceCertificatesTab({ deviceXref }: { deviceXref: string }) {
  const router = useRouter();
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(
    MACHINE_IDENTITY_CONFIG.list.defaultPageSize as number,
  );

  const certificatesQuery = useDeviceCertificates(deviceXref, {
    page,
    size: pageSize,
  });

  return (
    <PaginatedTableCard
      columns={CERTIFICATE_COLUMNS}
      page={certificatesQuery.data}
      isLoading={certificatesQuery.isPending}
      isFetching={certificatesQuery.isFetching}
      error={certificatesQuery.error}
      errorTitle="Unable to load certificates"
      errorDescription="This device's certificates could not be loaded."
      emptyMessage="No certificate has been issued to this device yet."
      onRetry={() => void certificatesQuery.refetch()}
      isRetrying={certificatesQuery.isFetching}
      minWidthClassName="min-w-5xl"
      // The device column is redundant here - every row is this device.
      defaultHiddenColumns={[...CERTIFICATE_DEFAULT_HIDDEN_COLUMNS, "device"]}
      getRowId={(certificate) => certificate.certificateXref}
      onRowClick={(certificate) =>
        router.push(
          `/machine-identity/device-certificates/${certificate.certificateXref}`,
        )
      }
      onPageChange={setPage}
      onPageSizeChange={(size) => {
        setPageSize(size);
        setPage(0);
      }}
    />
  );
}
