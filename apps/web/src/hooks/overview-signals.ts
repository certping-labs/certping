// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";

import { useDeploymentSummary } from "@/hooks/deployments";
import { useLatestSystemAlerts } from "@/hooks/incidents";
import { useAuth } from "@/hooks/use-auth";
import {
  fetchCertificateList,
  SSL_LIST_QUERY_KEY,
} from "@/hooks/use-certificate-list";
import {
  useFeatureFlags,
  useIsRouteAvailable,
} from "@/hooks/use-feature-flags";
import {
  canCreateCertificates,
  canViewCertificates,
  canViewDeployments,
  canViewAlerts,
} from "@/lib/authz";
import { getCertificateStatusGroup } from "@/lib/cert-manager/certificate-status";
import { getHighPriorityUnreadAlerts } from "@/lib/dashboard-triage";
import { buildNextSteps, type NextStep } from "@/lib/overview-next-steps";
import {
  buildRenewalForecast,
  type RenewalForecast,
} from "@/lib/overview-renewal-forecast";
import { getRemainingDays } from "@/lib/utils";

export interface CertificateSummary {
  total: number;
  active: number;
  expiring: number;
  pending: number;
  failed: number;
  expired: number;
}

export interface OverviewSignals {
  certificatesVisible: boolean;
  canIssueCertificates: boolean;
  certificateSummary: CertificateSummary | null;
  /** Expiries over the next twelve weeks; null until the certificates load. */
  renewalForecast: RenewalForecast | null;
  steps: NextStep[];
  isSettled: boolean;
  failedSources: string[];
  retryFailed: () => void;
}

interface SourceQuery {
  isError?: boolean;
  refetch?: () => unknown;
}

const isPendingCertificateStatus = (status: string): boolean => {
  const group = getCertificateStatusGroup(status);
  return group === "pending" || group === "needs-action";
};

export function useOverviewSignals(): OverviewSignals {
  const { user } = useAuth();
  const { isEnabled, isReady } = useFeatureFlags();
  const isRouteAvailable = useIsRouteAvailable();

  const certificatesVisible = canViewCertificates(user);
  const canIssueCertificates =
    isEnabled("CERTIFICATE_ISSUANCE") && canCreateCertificates(user);

  const certificatesQuery = useQuery({
    queryKey: [SSL_LIST_QUERY_KEY],
    queryFn: fetchCertificateList,
    enabled: certificatesVisible,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const deploymentsQuery = useDeploymentSummary({
    enabled:
      isReady &&
      isEnabled("CERTIFICATE_DEPLOYMENT") &&
      canViewDeployments(user),
  });
  const alertsQuery = useLatestSystemAlerts({
    enabled: isReady && isEnabled("ALERTS") && canViewAlerts(user),
  });

  const certificateSummary = useMemo<CertificateSummary | null>(() => {
    if (!certificatesQuery.data) return null;
    const summary = {
      total: 0,
      active: 0,
      expiring: 0,
      pending: 0,
      failed: 0,
      expired: 0,
    };
    for (const certificate of certificatesQuery.data) {
      summary.total += 1;
      if (certificate.status === "ACTIVE") summary.active += 1;
      if (certificate.status === "FAILED") summary.failed += 1;
      if (certificate.status === "EXPIRED") summary.expired += 1;
      if (isPendingCertificateStatus(certificate.status)) summary.pending += 1;
      const days = getRemainingDays(certificate.validTo ?? null);
      if (days !== null && days > 0 && days <= 30) summary.expiring += 1;
    }
    return summary;
  }, [certificatesQuery.data]);

  const renewalForecast = useMemo<RenewalForecast | null>(
    () =>
      certificatesQuery.data
        ? buildRenewalForecast(certificatesQuery.data)
        : null,
    [certificatesQuery.data],
  );

  const priorityAlerts = useMemo(
    () => getHighPriorityUnreadAlerts(alertsQuery.data ?? []).length,
    [alertsQuery.data],
  );
  const deploymentsFailed =
    (deploymentsQuery.data?.failed ?? 0) +
    (deploymentsQuery.data?.publishFailed ?? 0);
  const canReviewRenewals = isEnabled("CERTIFICATE_RENEWAL");

  const steps = useMemo(
    () =>
      buildNextSteps({
        totalCertificates: certificateSummary?.total ?? null,
        canIssueCertificates,
        certificatesExpiring: certificateSummary?.expiring ?? 0,
        certificatesFailed: certificateSummary?.failed ?? 0,
        deploymentsFailed,
        priorityAlerts,
        canReviewRenewals,
        isRouteAvailable,
      }),
    [
      canIssueCertificates,
      canReviewRenewals,
      certificateSummary,
      deploymentsFailed,
      isRouteAvailable,
      priorityAlerts,
    ],
  );

  const sources: ReadonlyArray<readonly [string, SourceQuery]> = [
    ["certificates", certificatesQuery],
    ["deployments", deploymentsQuery],
    ["alerts", alertsQuery],
  ];
  const failedKey = sources
    .filter(([, source]) => source.isError)
    .map(([name]) => name)
    .join("|");
  const failedSources = useMemo(
    () => (failedKey ? failedKey.split("|") : []),
    [failedKey],
  );
  const retryFailed = () => {
    for (const [, source] of sources) {
      if (source.isError) void source.refetch?.();
    }
  };

  return {
    certificatesVisible,
    canIssueCertificates,
    certificateSummary,
    renewalForecast,
    steps,
    isSettled:
      isReady &&
      !certificatesQuery.isLoading &&
      !deploymentsQuery.isLoading &&
      !alertsQuery.isLoading,
    failedSources,
    retryFailed,
  };
}
