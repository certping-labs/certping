// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { CertificateDetails } from "@/components/cert-manager/certificate/cert-page";
import {
  useGetCertificateDetails,
  useGetCertificateHistory,
} from "@/hooks/ssl";
import { Skeleton } from "@/components/ui/skeleton";
import { SidebarInset } from "@/components/ui/sidebar";
import React from "react";
import { redirect } from "next/navigation";
import { SomethingWentWrong } from "@/components/common/error";
import { useAuth } from "@/hooks/use-auth";
import { canViewCertificates } from "@/lib/authz";
import { Unauthorised } from "@/components/common/unautorised";
import { getApiErrorMessage } from "@/lib/backend/common";
import { errorReference } from "@/lib/correlation-id";
import type { CertificateHistoryItem } from "@/types/cert-manager";

const CURRENT_CERTIFICATE_STATUS_PRIORITY = ["ACTIVE", "RENEWING"] as const;

const getCurrentLifecycleCertificateXref = (
  items: CertificateHistoryItem[] | undefined,
): string | undefined => {
  if (!items?.length) {
    return undefined;
  }

  const firstCertificateByStatus = new Map<string, CertificateHistoryItem>();
  for (const item of items) {
    const status = item.status.trim().toUpperCase();
    if (!firstCertificateByStatus.has(status)) {
      firstCertificateByStatus.set(status, item);
    }
  }

  for (const status of CURRENT_CERTIFICATE_STATUS_PRIORITY) {
    const match = firstCertificateByStatus.get(status);
    if (match?.certificateXref) {
      return match.certificateXref;
    }
  }

  return undefined;
};

export default function CertificateDetail({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = React.use(params);
  const { user, isLoading: isLoadingAuth } = useAuth();
  const canAccessCertificate = canViewCertificates(user);
  const sslData = useGetCertificateDetails(id);
  const isHistoricalRenewalRecord =
    sslData.data?.status.trim().toUpperCase() === "RENEW_SUCCESS";
  const historyQuery = useGetCertificateHistory(
    sslData.data?.userDomainCertId,
    0,
    50,
    { pollWhile: isHistoricalRenewalRecord },
  );
  const currentLifecycleCertificateXref = React.useMemo(
    () => getCurrentLifecycleCertificateXref(historyQuery.data?.items),
    [historyQuery.data?.items],
  );

  const isReplacingHistoricalRenewalRoute =
    Boolean(currentLifecycleCertificateXref) &&
    currentLifecycleCertificateXref !== id &&
    isHistoricalRenewalRecord;

  // CERTIFICATE_ISSUANCE only gates creating new certs; viewing an existing one
  // is always allowed (subject to RBAC via canViewCertificates).

  if (isLoadingAuth) {
    return (
      <SidebarInset>
        <div className="p-6">
          <Skeleton className="mb-2 h-8 w-64" />
          <Skeleton className="h-4 w-40" />
        </div>
      </SidebarInset>
    );
  }

  if (!canAccessCertificate) {
    return (
      <SidebarInset>
        <div className="p-6">
          <Unauthorised />
        </div>
      </SidebarInset>
    );
  }

  if (sslData.isLoading) {
    return (
      <SidebarInset>
        <div className="p-6">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <Skeleton className="mb-2 h-8 w-64" />
              <Skeleton className="h-4 w-40" />
            </div>
            <Skeleton className="h-10 w-32" />
          </div>

          {/* Tabs skeleton */}
          <div className="mb-6 border-b">
            <div className="flex space-x-8">
              <Skeleton className="h-10 w-24" />
              <Skeleton className="h-10 w-24" />
              <Skeleton className="h-10 w-24" />
            </div>
          </div>

          {/* Content skeleton */}
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            <div className="space-y-4">
              <Skeleton className="h-6 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-6 w-3/4" />
              <Skeleton className="h-12 w-full" />
            </div>
            <div className="space-y-4">
              <Skeleton className="h-6 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-6 w-3/4" />
              <Skeleton className="h-12 w-full" />
            </div>
          </div>
        </div>
      </SidebarInset>
    );
  }

  if (sslData.isError || !sslData.data) {
    const errorMessage = getApiErrorMessage(
      sslData.error,
      "We could not retrieve the certificate details. Please try again later.",
    );

    return (
      <SidebarInset>
        <div className="p-6">
          <SomethingWentWrong
            title="Failed to load certificate details"
            description={errorMessage}
            reference={errorReference(sslData.error)}
            onRetry={() => void sslData.refetch()}
          />
        </div>
      </SidebarInset>
    );
  }

  if (isReplacingHistoricalRenewalRoute && currentLifecycleCertificateXref) {
    return redirect(
      `/cert-manager/manage/${encodeURIComponent(currentLifecycleCertificateXref)}`,
    );
  }

  return (
    <SidebarInset>
      <div className="min-h-screen bg-background p-6">
        <CertificateDetails certificate={sslData.data} />
      </div>
    </SidebarInset>
  );
}
