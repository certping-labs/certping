// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

import { SomethingWentWrong } from "@/components/common/error";
import { Unauthorised } from "@/components/common/unautorised";
import {
  DiscoveredCertDetailSkeleton,
  DiscoveredCertDetailView,
} from "@/components/cert-manager/discovery/discovered-cert-detail-view";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { SidebarInset } from "@/components/ui/sidebar";
import { useDiscoveredCertificate } from "@/hooks/discovery";
import { useAuth } from "@/hooks/use-auth";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { canCreateCertificates, canViewCertificates } from "@/lib/authz";
import { getApiErrorMessage } from "@/lib/backend/common";
import { errorReference } from "@/lib/correlation-id";

function parseDiscoveredCertId(
  raw: string | string[] | undefined,
): number | null {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

export default function DiscoveredCertDetailPage() {
  const routeParams = useParams<{ id: string }>();
  const certId = parseDiscoveredCertId(routeParams?.id);
  const { user, isLoading: isLoadingAuth } = useAuth();
  const canView = canViewCertificates(user);
  const isCertIssuanceEnabled = useIsFeatureEnabled("CERTIFICATE_ISSUANCE");
  const canIssue = isCertIssuanceEnabled && canCreateCertificates(user);

  const certQuery = useDiscoveredCertificate(certId, {
    enabled: canView && certId != null,
  });

  if (isLoadingAuth) {
    return (
      <SidebarInset>
        <DiscoveredCertDetailSkeleton />
      </SidebarInset>
    );
  }

  if (!canView) {
    return (
      <SidebarInset>
        <div className="p-6">
          <Unauthorised />
        </div>
      </SidebarInset>
    );
  }

  if (certId == null) {
    return (
      <SidebarInset>
        <div className="space-y-6 p-6">
          <PageHeader
            title="Invalid certificate"
            breadcrumbs={[
              { label: "Discovery", href: "/cert-manager/discovery" },
            ]}
            subtitle="The discovery certificate id in the URL is not valid."
          />
          <Card>
            <CardHeader>
              <CardTitle>Certificate not found</CardTitle>
            </CardHeader>
            <CardContent>
              <Button asChild variant="outline">
                <Link href="/cert-manager/discovery">Back to discovery</Link>
              </Button>
            </CardContent>
          </Card>
        </div>
      </SidebarInset>
    );
  }

  if (certQuery.isLoading) {
    return (
      <SidebarInset>
        <DiscoveredCertDetailSkeleton />
      </SidebarInset>
    );
  }

  if (certQuery.isError || !certQuery.data) {
    return (
      <SidebarInset>
        <div className="space-y-6 p-6">
          <PageHeader
            title={`Certificate #${certId}`}
            breadcrumbs={[
              { label: "Discovery", href: "/cert-manager/discovery" },
            ]}
            subtitle="Discovered certificate details"
          />
          <SomethingWentWrong
            title="Failed to load discovered certificate"
            description={getApiErrorMessage(
              certQuery.error,
              "We could not retrieve the discovered certificate details.",
            )}
            reference={errorReference(certQuery.error)}
            onRetry={() => void certQuery.refetch()}
          />
          <Button asChild variant="outline">
            <Link href="/cert-manager/discovery">Back to discovery</Link>
          </Button>
        </div>
      </SidebarInset>
    );
  }

  return (
    <SidebarInset>
      <div className="min-h-screen bg-background p-6">
        <DiscoveredCertDetailView cert={certQuery.data} canIssue={canIssue} />
      </div>
    </SidebarInset>
  );
}
