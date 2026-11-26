// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import Link from "next/link";
import {
  WarningIcon,
  CheckCircleIcon,
  CaretRightIcon,
  CopyIcon,
  ArrowSquareOutIcon,
} from "@phosphor-icons/react";

import { ProviderIcon } from "@/components/common/provider-icon";
import {
  compactValue,
  formatTargetType,
  getCertificateTitle,
  getExpirySummary,
  getInventoryBadgeVariant,
  getInventoryLabel,
  getManagedBadgeVariant,
  getManagedLabel,
  getOperationalFindings,
  uniqueValues,
} from "@/components/cert-manager/discovery/discovered-cert-detail-helpers";
import {
  DetailRows,
  DetailSection,
  StatusBadge,
  ValueList,
} from "@/components/cert-manager/discovery/discovered-cert-detail-primitives";
import { KubernetesDiscoveryPanel } from "@/components/cert-manager/discovery/kubernetes-discovery-detail";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { issueCertificateHref } from "@/lib/cert-manager/certificate-journeys";
import { getDiscoverySourceDetail } from "@/lib/cert-manager/discovery-source";
import { resolveCredentialProviderFromApiValue } from "@/lib/credential-providers";
import { cn, formatCertDate, formatDate, getSSLStatusBadge } from "@/lib/utils";
import type { DiscoveredCertDetail } from "@/types/discovery";

function CopyResourceButton({ value }: { value: string }) {
  const [hasCopied, setHasCopied] = React.useState(false);

  async function copyResourceId() {
    await navigator.clipboard.writeText(value);
    setHasCopied(true);
    window.setTimeout(() => setHasCopied(false), 1200);
  }

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={copyResourceId}
      aria-label="Copy resource ID"
    >
      <CopyIcon className="h-4 w-4" aria-hidden="true" />
      {hasCopied ? "Copied" : "Copy ID"}
    </Button>
  );
}

function DiscoveredCertificateHeader({
  cert,
  canIssue,
}: {
  cert: DiscoveredCertDetail;
  canIssue: boolean;
}) {
  const title = getCertificateTitle(cert);
  const reissueHref =
    canIssue && cert.managed === false && cert.domain
      ? issueCertificateHref({ domain: cert.domain })
      : null;
  const expirySummary = getExpirySummary(cert.notAfter);
  const sourceDetail = getDiscoverySourceDetail(cert.resourceId);

  return (
    <div>
      <div className="mb-4 flex items-center gap-2 text-sm">
        <Link
          href="/cert-manager/discovery"
          className="text-muted-foreground transition-colors hover:text-foreground"
        >
          Discovery
        </Link>
        <CaretRightIcon className="h-4 w-4 text-muted-foreground" />
        <span className="min-w-0 truncate font-medium text-foreground">
          {title}
        </span>
      </div>

      <div className="flex flex-col gap-4 rounded-md border border-border bg-card p-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <div className="mt-2 flex flex-wrap items-center gap-3">
              <h1 className="min-w-0 text-2xl font-semibold tracking-[-0.035em] wrap-break-word text-foreground">
                {title}
              </h1>
              {cert.certStatus ? (
                <Badge variant={getSSLStatusBadge(cert.certStatus)}>
                  {cert.certStatus.toUpperCase()}
                </Badge>
              ) : null}
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <StatusBadge variant={getManagedBadgeVariant(cert.managed)}>
                {getManagedLabel(cert.managed)}
              </StatusBadge>
              <StatusBadge
                variant={getInventoryBadgeVariant(cert.inventoryStatus)}
              >
                {getInventoryLabel(cert.inventoryStatus)}
              </StatusBadge>
              <StatusBadge variant={expirySummary.variant}>
                {expirySummary.label} remaining
              </StatusBadge>
            </div>
            <p className="mt-3 max-w-3xl text-sm leading-5 text-muted-foreground">
              Discovered from {formatTargetType(cert.targetType)} on{" "}
              {formatCertDate(cert.discoveredAt)}.{" "}
              {sourceDetail
                ? `Provider location: ${sourceDetail}.`
                : "Provider resource ID is shown in the source panel."}
            </p>
          </div>
          {reissueHref ? (
            <Button asChild className="shrink-0">
              <Link href={reissueHref}>Reissue with CertPing</Link>
            </Button>
          ) : null}
        </div>

        <div className="rounded-md border border-border bg-background p-3">
          <div className="flex items-start gap-3">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-md border border-border bg-card">
              <ProviderIcon
                provider={
                  resolveCredentialProviderFromApiValue(cert.targetType) ??
                  "aws"
                }
                serviceApiValue={cert.targetType}
                size={24}
              />
            </div>
            <div className="min-w-0">
              <div className="text-xs font-medium text-muted-foreground">
                Provider resource
              </div>
              <div className="mt-1 font-mono text-xs leading-5 break-all text-foreground">
                {cert.resourceId}
              </div>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <CopyResourceButton value={cert.resourceId} />
            <Button asChild variant="ghost" size="sm">
              <Link href="/cert-manager/discovery">
                Inventory
                <ArrowSquareOutIcon className="h-4 w-4" aria-hidden="true" />
              </Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function OperationalReview({ cert }: { cert: DiscoveredCertDetail }) {
  const findings = getOperationalFindings(cert);
  const leadFinding = findings[0];
  const hasCritical = findings.some(
    (finding) => finding.variant === "destructive",
  );

  return (
    <section
      className={cn(
        "rounded-lg border bg-card",
        hasCritical ? "border-destructive/30" : "border-border",
      )}
    >
      <div className="flex flex-col gap-3 border-b border-border px-5 py-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex items-start gap-3">
          <div
            className={cn(
              "mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-md border",
              leadFinding.variant === "success"
                ? "border-success-border bg-success-soft text-success"
                : hasCritical
                  ? "border-danger-border bg-danger-soft text-destructive"
                  : "border-warning-100 bg-warning-50 text-warning",
            )}
          >
            {leadFinding.variant === "success" ? (
              <CheckCircleIcon className="h-4 w-4" aria-hidden="true" />
            ) : (
              <WarningIcon className="h-4 w-4" aria-hidden="true" />
            )}
          </div>
          <div>
            <h2 className="text-base font-semibold tracking-[-0.02em] text-foreground">
              Risk and impact
            </h2>
            <p className="mt-1 max-w-3xl text-sm leading-5 text-muted-foreground">
              {leadFinding.title}: {leadFinding.description}
            </p>
          </div>
        </div>
        <Badge variant={leadFinding.variant} includeDot>
          {leadFinding.variant === "success" ? "Clear" : "Needs review"}
        </Badge>
      </div>

      <div className="flex flex-col gap-2 p-4">
        {findings.map((finding) => (
          <div
            key={`${finding.title}-${finding.description}`}
            className={cn(
              "rounded-lg border px-3 py-2.5",
              finding.variant === "destructive"
                ? "border-danger-border bg-danger-soft/40"
                : finding.variant === "warning"
                  ? "border-warning-100 bg-warning-50/40"
                  : "border-border bg-background",
            )}
          >
            <Badge variant={finding.variant}>{finding.title}</Badge>
            <p className="mt-2 min-w-0 text-sm leading-5 font-semibold wrap-break-word text-muted-foreground">
              {finding.description}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}

function DomainAndUsagePanel({ cert }: { cert: DiscoveredCertDetail }) {
  const domains = uniqueValues([cert.domain ?? "", ...cert.sanDomains]);

  return (
    <DetailSection title="Names and usage hints">
      <div className="space-y-5">
        <div className="space-y-2">
          <div className="text-xs font-medium text-muted-foreground">
            Domain coverage ({domains.length})
          </div>
          <ValueList
            values={domains}
            emptyLabel="No domain coverage reported."
          />
        </div>
        <div className="space-y-2">
          <div className="text-xs font-medium text-muted-foreground">
            Reported usage hints ({cert.inUseBy.length})
          </div>
          <ValueList
            values={cert.inUseBy}
            emptyLabel="No usage hints reported."
          />
        </div>
      </div>
    </DetailSection>
  );
}

function MetadataGroup({
  title,
  items,
  className,
}: {
  title: string;
  items: React.ComponentProps<typeof DetailRows>["items"];
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-lg border border-border bg-background p-4",
        className,
      )}
    >
      <h3 className="mb-2 text-sm font-semibold text-foreground">{title}</h3>
      <DetailRows items={items} />
    </div>
  );
}

function CertificateMetadataGrid({ cert }: { cert: DiscoveredCertDetail }) {
  const sourceDetail = getDiscoverySourceDetail(cert.resourceId);
  const source = cert.providerData?.source;

  return (
    <DetailSection
      title="Certificate metadata"
      description="Merged source, certificate, and cryptographic fields without repeating resource IDs or serials."
      className="w-full"
    >
      <div className="grid gap-4 xl:grid-cols-3">
        <MetadataGroup
          title="Identity"
          items={[
            {
              label: "Primary domain",
              value: compactValue(cert.domain),
              mono: true,
            },
            {
              label: "Subject DN",
              value: compactValue(cert.subjectDn),
              mono: true,
            },
            {
              label: "Serial number",
              value: compactValue(cert.serialNumber),
              mono: true,
            },
            { label: "Issuer", value: compactValue(cert.issuer) },
          ]}
        />
        <MetadataGroup
          title="Validity"
          items={[
            { label: "Valid from", value: formatCertDate(cert.notBefore) },
            { label: "Valid until", value: formatCertDate(cert.notAfter) },
            {
              label: "Last discovered",
              value: formatCertDate(cert.discoveredAt),
            },
            {
              label: "Missing since",
              value: cert.missingSince ? formatDate(cert.missingSince) : "-",
            },
          ]}
        />
        <MetadataGroup
          title="Provider"
          className="xl:col-span-1"
          items={[
            {
              label: "Source",
              value: formatTargetType(cert.targetType),
            },
            {
              label: "Location",
              value: sourceDetail ?? "-",
              mono: true,
            },
            {
              label: "Resource",
              value: cert.resourceId,
              mono: true,
            },
          ]}
        />
        <MetadataGroup
          title="Cryptography"
          className="xl:col-span-2"
          items={[
            {
              label: "Certificate type",
              value: compactValue(cert.certType),
            },
            {
              label: "Key algorithm",
              value: compactValue(cert.keyAlgorithm),
              mono: true,
            },
            {
              label: "Signature",
              value: compactValue(cert.signatureAlgorithm),
              mono: true,
            },
            {
              label: "Key usage",
              value: compactValue(cert.keyUsage),
              mono: true,
            },
            {
              label: "Extended usage",
              value: compactValue(cert.extendedKeyUsage),
              mono: true,
            },
          ]}
        />
        {cert.providerData ? (
          <MetadataGroup
            title="Kubernetes source"
            items={[
              {
                label: "Cluster",
                value: compactValue(cert.providerData.clusterName),
                mono: true,
              },
              {
                label: "Scan status",
                value:
                  cert.providerData.usageComplete &&
                  cert.providerData.impactComplete
                    ? "Complete"
                    : "Partial",
              },
              {
                label: "Secret",
                value:
                  source?.namespace && source?.name
                    ? `${source.namespace}/${source.name}`
                    : compactValue(source?.name),
                mono: true,
              },
              { label: "Kind", value: compactValue(source?.kind) },
              { label: "Type", value: compactValue(source?.type), mono: true },
              {
                label: "Fingerprint",
                value: compactValue(source?.fingerprintSha256),
                mono: true,
              },
              {
                label: "API version",
                value: compactValue(source?.apiVersion),
                mono: true,
              },
              {
                label: "UID",
                value: compactValue(source?.uid),
                mono: true,
              },
            ]}
          />
        ) : null}
      </div>
    </DetailSection>
  );
}

function ExpiryAlerts({ cert }: { cert: DiscoveredCertDetail }) {
  const expirySummary = getExpirySummary(cert.notAfter);
  const isExpiringSoon =
    expirySummary.remainingDays !== null &&
    expirySummary.remainingDays <= 30 &&
    expirySummary.remainingDays >= 0 &&
    (cert.certStatus ?? "").toUpperCase() !== "EXPIRED";

  return (
    <>
      {isExpiringSoon ? (
        <Alert className="border-warning-100 bg-warning-50/70">
          <WarningIcon className="h-4 w-4 text-warning" />
          <AlertDescription>
            <span className="font-medium text-foreground">
              Certificate expires in {expirySummary.remainingDays} days.
            </span>{" "}
            Renew before {formatCertDate(cert.notAfter)}.
          </AlertDescription>
        </Alert>
      ) : null}

      {cert.inventoryStatus === "MISSING" ? (
        <Alert className="border-danger-border bg-danger-soft/50">
          <WarningIcon className="h-4 w-4 text-destructive" />
          <AlertDescription>
            This certificate was not found in the latest discovery scan
            {cert.missingSince ? ` since ${formatDate(cert.missingSince)}` : ""}
            .
          </AlertDescription>
        </Alert>
      ) : null}
    </>
  );
}

export function DiscoveredCertDetailSkeleton() {
  return (
    <div className="w-full space-y-5 p-6" role="status" aria-label="Loading">
      <Skeleton className="h-40 w-full rounded-md" />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Skeleton className="h-24 rounded-md" />
        <Skeleton className="h-24 rounded-md" />
        <Skeleton className="h-24 rounded-md" />
        <Skeleton className="h-24 rounded-md" />
      </div>
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <Skeleton className="h-80 rounded-md" />
        <Skeleton className="h-80 rounded-md" />
      </div>
    </div>
  );
}

export function DiscoveredCertDetailView({
  cert,
  canIssue = false,
}: {
  cert: DiscoveredCertDetail;
  canIssue?: boolean;
}) {
  return (
    <div className="w-full space-y-5">
      <DiscoveredCertificateHeader cert={cert} canIssue={canIssue} />
      <ExpiryAlerts cert={cert} />

      <main className="min-w-0 space-y-5">
        <OperationalReview cert={cert} />
        {cert.providerData ? (
          <KubernetesDiscoveryPanel data={cert.providerData} />
        ) : null}
        <DomainAndUsagePanel cert={cert} />
        <CertificateMetadataGrid cert={cert} />
      </main>
    </div>
  );
}
