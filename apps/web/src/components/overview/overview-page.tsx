// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { Unauthorised } from "@/components/common/unautorised";
import { MachineIdentityDashboardOverview } from "@/components/machine-identity/dashboard-overview";
import { CertificatesSummary } from "@/components/overview/certificates-summary";
import { NextStepsPanel } from "@/components/overview/next-steps-panel";
import { QuickActions } from "@/components/overview/quick-actions";
import { RenewalForecastPanel } from "@/components/overview/renewal-forecast";
import { AgentsCard } from "@/components/overview/agents-card";
import { ValueSummaryPanel } from "@/components/overview/value-summary";
import { PageHeader } from "@/components/ui/page-header";
import { useOverviewSignals } from "@/hooks/overview-signals";
import { useAuth } from "@/hooks/use-auth";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import {
  canViewCredentials,
  canViewDeployments,
  canViewAlerts,
} from "@/lib/authz";

export function OverviewPage() {
  const { user, isLoading } = useAuth();
  const signals = useOverviewSignals();
  const isAgentHealthEnabled = useIsFeatureEnabled("AGENT_HEALTH_MONITORING");
  // Mounting the panel fires its device and connector queries, so it waits
  // for Machine Identity to be confirmed on.
  const isMachineIdentityEnabled = useIsFeatureEnabled("IOT_DEVICE_MANAGEMENT");
  const isRenewalEnabled = useIsFeatureEnabled("CERTIFICATE_RENEWAL");

  const hasAccess =
    signals.certificatesVisible ||
    canViewDeployments(user) ||
    canViewCredentials(user) ||
    canViewAlerts(user);

  if (!isLoading && !hasAccess) {
    return (
      <div className="p-6">
        <Unauthorised />
      </div>
    );
  }

  return (
    <div className="w-full space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Overview"
        subtitle="Your certificates, deployments and alerts in one place."
      />

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0 space-y-6">
          <NextStepsPanel
            steps={signals.steps}
            isLoading={!signals.isSettled}
            failedSources={signals.failedSources}
            onRetry={signals.retryFailed}
          />

          {signals.certificatesVisible ? (
            <CertificatesSummary
              summary={signals.certificateSummary}
              canIssue={signals.canIssueCertificates}
            />
          ) : null}

          <ValueSummaryPanel enabled={signals.certificatesVisible} />

          {signals.certificatesVisible ? (
            <RenewalForecastPanel
              forecast={signals.renewalForecast}
              renewalsHref={
                isRenewalEnabled ? "/cert-manager/rotation" : "/cert-manager"
              }
            />
          ) : null}

          {isMachineIdentityEnabled ? (
            <MachineIdentityDashboardOverview />
          ) : null}

          {isAgentHealthEnabled ? <AgentsCard /> : null}
        </div>

        <aside aria-label="Quick actions" className="space-y-6">
          <QuickActions
            canIssueCertificates={signals.canIssueCertificates}
            canViewDeployments={canViewDeployments(user)}
          />
        </aside>
      </div>
    </div>
  );
}
