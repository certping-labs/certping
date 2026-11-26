// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Image from "next/image";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  SealCheckIcon,
  ClockIcon,
  ArrowSquareOutIcon,
  CertificateIcon,
  GlobeIcon,
  RocketIcon,
  ShieldCheckIcon,
} from "@phosphor-icons/react";

import { SomethingWentWrong } from "@/components/common/error";
import { Unauthorised } from "@/components/common/unautorised";
import { SupportReferenceLink } from "@/components/support/support-reference-link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { SidebarInset } from "@/components/ui/sidebar";
import {
  useDeploymentByRequestId,
  useDeploymentCredentialReference,
  useDeploymentLiveCertificate,
} from "@/hooks/deployments";
import { useAuth } from "@/hooks/use-auth";
import {
  canCreateDeployments,
  canViewCertificates,
  canViewDeployments,
} from "@/lib/authz";
import { getApiErrorMessage } from "@/lib/backend/common";
import { errorReference } from "@/lib/correlation-id";
import { formatDeploymentFlowType } from "@/lib/deployment-flow";
import {
  formatDeploymentStatusLabel,
  getCredentialPresentation,
  getDeploymentStatusBadgeVariant,
  getProviderCardDetails,
  getSnapshotHealthLabel,
  getTriggeredBy,
  getTriggeredByBadgeVariant,
} from "@/lib/cert-manager/deployment-details-page-helpers";
import { cn, formatDateTime } from "@/lib/utils";

export default function DeploymentDetailsPage() {
  const routeParams = useParams<{
    userDomainCertificateId: string;
    requestId: string;
  }>();
  const userDomainCertificateId = Array.isArray(
    routeParams?.userDomainCertificateId,
  )
    ? routeParams.userDomainCertificateId[0] || ""
    : routeParams?.userDomainCertificateId || "";
  const requestId = Array.isArray(routeParams?.requestId)
    ? routeParams.requestId[0] || ""
    : routeParams?.requestId || "";
  const { user, isLoading: isLoadingAuth } = useAuth();
  const canView = canViewDeployments(user);
  const canCreate = canCreateDeployments(user);
  const canViewCertificate = canViewCertificates(user);

  const deploymentQuery = useDeploymentByRequestId(requestId);
  const deployment = deploymentQuery.data;
  const domain = deployment?.domain || deployment?.certificateXref || requestId;

  const certificateQuery = useDeploymentLiveCertificate(
    deployment?.certificateXref,
  );
  const credentialQuery = useDeploymentCredentialReference(
    deployment?.deploymentCredentialXref,
  );

  const targetPresentation = getProviderCardDetails(
    deployment?.targetType,
    "Deployment target",
  );
  const credentialPresentation = getCredentialPresentation(
    credentialQuery.data,
    deployment,
  );

  if (isLoadingAuth || deploymentQuery.isLoading) {
    return <DeploymentDetailsSkeleton />;
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

  if (deploymentQuery.isError) {
    return (
      <SidebarInset>
        <div className="p-6">
          <SomethingWentWrong
            title="Failed to load deployment details"
            description={getApiErrorMessage(
              deploymentQuery.error,
              "We could not retrieve the deployment request details.",
            )}
            reference={errorReference(deploymentQuery.error)}
            onRetry={() => void deploymentQuery.refetch()}
          />
        </div>
      </SidebarInset>
    );
  }

  if (!deployment) {
    return (
      <SidebarInset>
        <div className="space-y-6 p-6">
          <PageHeader
            title={requestId}
            breadcrumbs={[
              { label: "Deployments", href: "/cert-manager/deployments" },
              {
                label: "History",
                href: `/cert-manager/deployments/${encodeURIComponent(userDomainCertificateId)}`,
              },
            ]}
            subtitle="Deployment execution details"
          />
          <Card>
            <CardHeader>
              <CardTitle>Deployment not found</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-sm text-muted-foreground">
              <p>
                No deployment request was found for request ID{" "}
                <strong>{requestId}</strong>.
              </p>
              <p>
                <Link
                  href={`/cert-manager/deployments/${encodeURIComponent(userDomainCertificateId)}`}
                  className="font-medium text-primary transition-colors hover:underline"
                >
                  Return to deployment history
                </Link>
              </p>
            </CardContent>
          </Card>
        </div>
      </SidebarInset>
    );
  }

  const deploymentStatus = deployment.status.toUpperCase();

  return (
    <SidebarInset>
      <div className="w-full space-y-6 p-6">
        <Card className="overflow-hidden">
          <CardContent className="space-y-4 p-6">
            <PageHeader
              title={domain}
              breadcrumbs={[
                { label: "Deployments", href: "/cert-manager/deployments" },
                {
                  label: "History",
                  href: `/cert-manager/deployments/${encodeURIComponent(userDomainCertificateId)}`,
                },
              ]}
              subtitle={`Deployment execution details for request ${requestId}`}
              actions={
                <div className="flex w-full flex-wrap justify-start gap-2 md:justify-end">
                  {canViewCertificate && deployment.certificateXref ? (
                    <Button
                      asChild
                      variant="outline"
                      className="w-full md:w-fit"
                    >
                      <Link
                        href={`/cert-manager/manage/${encodeURIComponent(
                          deployment.certificateXref,
                        )}`}
                      >
                        <ArrowSquareOutIcon className="h-4 w-4" />
                        Open certificate
                      </Link>
                    </Button>
                  ) : null}
                  {canCreate && deployment.certificateXref ? (
                    <Button asChild className="w-full md:w-fit">
                      <Link
                        href={`/cert-manager/deployments/${encodeURIComponent(userDomainCertificateId)}?deployCertificateXref=${encodeURIComponent(
                          deployment.certificateXref,
                        )}`}
                      >
                        New deployment
                      </Link>
                    </Button>
                  ) : null}
                </div>
              }
            />

            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={getDeploymentStatusBadgeVariant(deployment.status)}
                textOnly
                className="capitalize"
              >
                {formatDeploymentStatusLabel(deployment.status)}
              </Badge>
              <Badge
                variant={getTriggeredByBadgeVariant(getTriggeredBy(deployment))}
                textOnly
                className="capitalize"
              >
                {formatDeploymentStatusLabel(getTriggeredBy(deployment))}
              </Badge>
              <Badge variant="secondary" textOnly className="capitalize">
                {formatDeploymentFlowType(deployment.flowType)}
              </Badge>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <HeaderMetric
                icon={<GlobeIcon className="h-4 w-4" />}
                label="Domain"
                value={domain}
              />
              <HeaderMetric
                icon={<SealCheckIcon className="h-4 w-4" />}
                label="Snapshot health"
                value={getSnapshotHealthLabel(deployment)}
                tone={deployment.userMessage ? "warning" : "neutral"}
              />
              <HeaderMetric
                icon={<ClockIcon className="h-4 w-4" />}
                label="Requested"
                value={formatDateTime(
                  deployment.requestedAt || deployment.createdAt || null,
                )}
              />
              <HeaderMetric
                icon={<RocketIcon className="h-4 w-4" />}
                label="Target"
                value={targetPresentation.label}
              />
            </div>
          </CardContent>
        </Card>

        <section className="grid gap-4 md:grid-cols-3">
          <ProviderSummaryCard
            icon={<RocketIcon className="h-4 w-4" />}
            label="Deployment target"
            title={targetPresentation.label}
            subtitle={deployment.targetType || "-"}
            logo={targetPresentation.logo}
          />
          <ProviderSummaryCard
            icon={<ShieldCheckIcon className="h-4 w-4" />}
            label="Deployment credential"
            title={credentialPresentation.title}
            subtitle={credentialPresentation.subtitle}
            logo={credentialPresentation.logo}
          />
          <ProviderSummaryCard
            icon={<CertificateIcon className="h-4 w-4" />}
            label="Certificate reference"
            title={domain}
            subtitle={deployment.certificateXref || "No certificate xref"}
            monoSubtitle
          />
        </section>

        <section className="grid gap-4 xl:grid-cols-[1.3fr_0.7fr]">
          <Card>
            <CardHeader>
              <CardTitle>Execution timeline</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <TimelineRow
                label="Requested"
                value={formatDateTime(
                  deployment.requestedAt || deployment.createdAt || null,
                )}
                helper="Deployment request accepted"
              />
              <TimelineRow
                label="Published"
                value={formatDateTime(deployment.publishedAt || null)}
                helper="Message handed to deployment worker"
              />
              <TimelineRow
                label="Responded"
                value={formatDateTime(deployment.respondedAt || null)}
                helper="Worker returned deployment status"
              />
              <TimelineRow
                label="Completed"
                value={formatDateTime(deployment.completedAt || null)}
                helper="Final terminal state"
                emphasize={deploymentStatus === "SUCCESS"}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Execution summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-sm text-muted-foreground">
              <SummaryRow
                label="Request ID"
                value={deployment.requestId || "-"}
                mono
              />
              <SummaryRow
                label="Correlation ID"
                value={deployment.correlationId || "-"}
                mono
              />
              <SummaryRow label="Source" value={deployment.source || "-"} />
              <SummaryRow
                label="Trigger"
                value={formatDeploymentStatusLabel(getTriggeredBy(deployment))}
              />
              <SummaryRow
                label="Target resource"
                value={deployment.targetResourceId || "-"}
                mono
              />
            </CardContent>
          </Card>
        </section>

        {deployment.userMessage ? (
          <Card className="border-destructive/30 bg-destructive/5">
            <CardHeader>
              <CardTitle className="text-destructive">
                Failure details
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <SummaryRow
                label="What happened"
                value={deployment.userMessage}
              />
              <SupportReferenceLink
                correlationId={deployment.correlationId}
                summary={
                  deployment.domain
                    ? `Certificate deployment failed for ${deployment.domain}`
                    : "Certificate deployment failed"
                }
                message={deployment.userMessage}
                domain={deployment.domain}
              />
            </CardContent>
          </Card>
        ) : null}

        <section className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
          <Card>
            <CardHeader>
              <CardTitle>Certificate snapshot</CardTitle>
            </CardHeader>
            <CardContent>
              {certificateQuery.isLoading ? (
                <CertificateSnapshotSkeleton />
              ) : certificateQuery.isError ? (
                <InlineError message="Current certificate details are unavailable." />
              ) : certificateQuery.data ? (
                <div className="grid gap-3 text-sm text-muted-foreground sm:grid-cols-2">
                  <SummaryRow
                    label="Certificate Xref"
                    value={certificateQuery.data.certificateXref || "-"}
                    mono
                  />
                  <SummaryRow
                    label="Issuer"
                    value={certificateQuery.data.issuer || "-"}
                  />
                  <SummaryRow
                    label="Valid from"
                    value={formatDateTime(
                      certificateQuery.data.validFrom || null,
                    )}
                  />
                  <SummaryRow
                    label="Valid to"
                    value={formatDateTime(
                      certificateQuery.data.validTo || null,
                    )}
                  />
                  <SummaryRow
                    label="Serial number"
                    value={certificateQuery.data.serialNumber || "-"}
                    mono
                  />
                  <SummaryRow
                    label="Fingerprint"
                    value={certificateQuery.data.fingerprintSha256 || "-"}
                    mono
                  />
                </div>
              ) : (
                <InlineError message="No live certificate snapshot is available for this deployment." />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Credential snapshot</CardTitle>
            </CardHeader>
            <CardContent>
              {credentialQuery.isLoading ? (
                <CredentialSnapshotSkeleton />
              ) : credentialQuery.isError ? (
                <InlineError message="Credential details are unavailable." />
              ) : credentialQuery.data ? (
                <div className="space-y-3 text-sm text-muted-foreground">
                  <SummaryRow
                    label="Credential"
                    value={
                      credentialQuery.data.description ||
                      credentialQuery.data.credentialXref
                    }
                  />
                  <SummaryRow
                    label="Type"
                    value={
                      credentialQuery.data.targetType ||
                      credentialQuery.data.provider ||
                      "-"
                    }
                  />
                  <SummaryRow
                    label="Status"
                    value={credentialQuery.data.status || "-"}
                  />
                  <SummaryRow
                    label="Reference"
                    value={credentialQuery.data.credentialXref}
                    mono
                  />
                </div>
              ) : (
                <InlineError message="No credential metadata is available for this deployment." />
              )}
            </CardContent>
          </Card>
        </section>
      </div>
    </SidebarInset>
  );
}

function HeaderMetric({
  icon,
  label,
  value,
  tone = "neutral",
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone?: "neutral" | "warning";
}) {
  return (
    <div
      className={cn(
        "min-w-0 rounded-xl border px-4 py-3",
        tone === "warning" ? "border-warning-200 bg-warning-50/70" : "bg-card",
      )}
    >
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        {icon}
        {label}
      </div>
      <div
        className="mt-2 truncate text-sm font-medium text-foreground"
        title={value}
      >
        {value}
      </div>
    </div>
  );
}

function ProviderSummaryCard({
  icon,
  label,
  title,
  subtitle,
  logo,
  monoSubtitle = false,
}: {
  icon: React.ReactNode;
  label: string;
  title: string;
  subtitle: string;
  logo?: string;
  monoSubtitle?: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex items-start gap-4 p-5">
        <div className="flex size-10 items-center justify-center rounded-xl border bg-muted/40 text-muted-foreground">
          {logo ? (
            <Image
              src={logo}
              alt=""
              width={20}
              height={20}
              className="h-5 w-5 object-contain"
            />
          ) : (
            icon
          )}
        </div>
        <div className="min-w-0 space-y-1">
          <div className="text-xs text-muted-foreground">{label}</div>
          <div className="text-sm font-semibold break-all text-foreground">
            {title}
          </div>
          <div
            className={cn(
              "text-sm text-muted-foreground",
              monoSubtitle && "font-mono text-xs break-all",
            )}
          >
            {subtitle?.replaceAll("_", " ") || "-"}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function TimelineRow({
  label,
  value,
  helper,
  emphasize = false,
}: {
  label: string;
  value: string;
  helper: string;
  emphasize?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b pb-4 last:border-b-0 last:pb-0">
      <div>
        <div className="text-sm font-medium text-foreground">{label}</div>
        <div className="text-xs text-muted-foreground">{helper}</div>
      </div>
      <div
        className={cn(
          "text-right text-sm text-muted-foreground",
          emphasize && "font-medium text-foreground",
        )}
      >
        {value}
      </div>
    </div>
  );
}

function SummaryRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div
        className={cn(
          "text-sm text-foreground",
          mono && "font-mono text-xs break-all",
        )}
      >
        {value}
      </div>
    </div>
  );
}

function InlineError({ message }: { message: string }) {
  return <div className="text-sm text-muted-foreground">{message}</div>;
}

function CertificateSnapshotSkeleton() {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {Array.from({ length: 6 }).map((_, index) => (
        <Skeleton key={index} className="h-14 w-full" />
      ))}
    </div>
  );
}

function CredentialSnapshotSkeleton() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 4 }).map((_, index) => (
        <Skeleton key={index} className="h-14 w-full" />
      ))}
    </div>
  );
}

function DeploymentDetailsSkeleton() {
  return (
    <SidebarInset>
      <div className="space-y-6 p-6">
        <Skeleton className="h-40 w-full" />
        <div className="grid gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <Skeleton key={index} className="h-28 w-full" />
          ))}
        </div>
        <div className="grid gap-4 xl:grid-cols-[1.3fr_0.7fr]">
          <Skeleton className="h-64 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    </SidebarInset>
  );
}
