// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import Link from "next/link";
import type { ColumnDef } from "@tanstack/react-table";
import {
  WarningIcon,
  ArrowRightIcon,
  CaretRightIcon,
  StackIcon,
  CrosshairIcon,
  BinocularsIcon,
  ShieldWarningIcon,
} from "@phosphor-icons/react";

import { ProviderIcon } from "@/components/common/provider-icon";
import { MetricCard, MetricStrip } from "@/components/common/metric-card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  credentialDetailHref,
  DISCOVERY_SOURCE_OPTIONS,
  formatDiscoveryTargetLabel,
  getCertStatusBadgeVariant,
  getExpiryTextVariant,
  getExpiryBadgeVariant,
  getManagedBadgeVariant,
  getManagedLabel,
  isExpiredAt,
  isExpiringWithinDays,
  isUnmanagedDiscoveredCert,
} from "@/lib/cert-manager/discovery-display";
import { issueCertificateHref } from "@/lib/cert-manager/certificate-journeys";
import { getDiscoverySourceDetail } from "@/lib/cert-manager/discovery-source";
import { resolveCredentialProviderFromApiValue } from "@/lib/credential-providers";
import { humanizeEnum } from "@/lib/humanize";
import { cn, formatDate } from "@/lib/utils";
import type { DiscoveredCert } from "@/types/discovery";

function SourceLogo({
  targetType,
  size = 22,
}: {
  targetType: string | null | undefined;
  size?: number;
}) {
  return (
    <ProviderIcon
      provider={
        resolveCredentialProviderFromApiValue(targetType ?? "") ?? "aws"
      }
      serviceApiValue={targetType ?? undefined}
      size={size}
      className="shrink-0"
    />
  );
}

function SourceSummary({ cert }: { cert: DiscoveredCert }) {
  const credentialXref = cert.credentialXref ?? null;
  const sourceDetail = getDiscoverySourceDetail(cert.resourceId);

  return (
    <div className="flex min-w-0 items-center gap-2.5">
      <SourceLogo targetType={cert.targetType} />
      <div className="min-w-0">
        <div className="truncate text-sm font-medium text-foreground">
          {formatDiscoveryTargetLabel(cert.targetType)}
        </div>
        {credentialXref ? (
          <Link
            href={credentialDetailHref(credentialXref)}
            className="block max-w-[200px] truncate font-mono text-xs text-primary hover:underline"
            title={`View credential ${credentialXref}`}
            onClick={(event) => event.stopPropagation()}
          >
            {credentialXref}
          </Link>
        ) : sourceDetail ? (
          <span
            className="block max-w-[200px] truncate font-mono text-xs text-muted-foreground/70"
            title={cert.resourceId}
          >
            {sourceDetail}
          </span>
        ) : null}
      </div>
    </div>
  );
}

function ExpiryCell({ notAfter }: { notAfter: string | null }) {
  if (!notAfter) {
    return <span className="text-sm text-muted-foreground">-</span>;
  }

  const suffix = isExpiredAt(notAfter)
    ? "expired"
    : isExpiringWithinDays(notAfter, 30)
      ? "soon"
      : null;

  return (
    <div
      className={cn(
        "flex flex-col gap-1",
        `text-${getExpiryTextVariant(notAfter)}`,
      )}
    >
      {suffix ? `${formatDate(notAfter)} ${suffix}` : formatDate(notAfter)}
    </div>
  );
}

export const DISCOVERY_HIDDEN_COLUMNS = ["notBefore", "discoveredAt"];

export const DISCOVERY_COLUMNS: ColumnDef<DiscoveredCert>[] = [
  {
    accessorKey: "domain",
    header: "Certificate",
    size: 300,
    cell: ({ row }) => {
      const cert = row.original;
      const sanCount = cert.sanDomains?.length ?? 0;
      const manageHref =
        cert.managed === true && cert.managedCertificateXref
          ? `/cert-manager/manage/${encodeURIComponent(cert.managedCertificateXref)}`
          : null;

      return (
        <div className="min-w-0 py-0.5">
          {manageHref ? (
            <Link
              href={manageHref}
              className="block truncate text-sm font-medium text-primary hover:underline"
              title={`View managed certificate for ${cert.domain ?? "this certificate"}`}
              onClick={(event) => event.stopPropagation()}
            >
              {cert.domain ?? "-"}
            </Link>
          ) : (
            <div
              className="truncate text-sm font-medium text-foreground"
              title={cert.domain ?? "-"}
            >
              {cert.domain ?? <span className="text-muted-foreground">-</span>}
            </div>
          )}
          {sanCount > 0 ? (
            <div className="mt-0.5 text-xs text-muted-foreground">
              +{sanCount} SAN {sanCount === 1 ? "name" : "names"}
            </div>
          ) : null}
        </div>
      );
    },
  },
  {
    accessorKey: "targetType",
    header: "Source",
    cell: ({ row }) => <SourceSummary cert={row.original} />,
  },
  {
    accessorKey: "certStatus",
    header: "Status",
    cell: ({ row }) => (
      <Badge variant={getCertStatusBadgeVariant(row.original.certStatus)}>
        {humanizeEnum(row.original.certStatus) || "Unknown"}
      </Badge>
    ),
  },
  {
    accessorKey: "keyAlgorithm",
    header: "Key algorithm",
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground">
        {row.original.keyAlgorithm ?? "Unknown"}
      </span>
    ),
  },
  {
    accessorKey: "managed",
    header: "Managed",
    cell: ({ row }) => (
      <Badge variant={getManagedBadgeVariant(row.original.managed)}>
        {getManagedLabel(row.original.managed)}
      </Badge>
    ),
  },
  {
    accessorKey: "notBefore",
    header: "Issued on",
    cell: ({ row }) => {
      const issuedAt = row.original.notBefore;
      return (
        <span className="text-sm text-muted-foreground">
          {issuedAt ? formatDate(issuedAt) : "-"}
        </span>
      );
    },
  },
  {
    accessorKey: "notAfter",
    header: "Expires on",
    cell: ({ row }) => <ExpiryCell notAfter={row.original.notAfter} />,
  },
  {
    accessorKey: "discoveredAt",
    header: "Discovered",
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground">
        {formatDate(row.original.discoveredAt)}
      </span>
    ),
  },
  {
    id: "open",
    header: () => <span className="sr-only">Open details</span>,
    cell: () => (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors group-hover:text-primary">
        Open
        <CaretRightIcon className="h-3.5 w-3.5" aria-hidden="true" />
      </span>
    ),
    size: 88,
  },
];

function UnmanagedCallout({
  unmanaged,
  expiring,
  canIssue,
  onReview,
  focusDomain,
  sourceLabel,
}: {
  unmanaged: number;
  expiring: number;
  canIssue: boolean;
  onReview?: () => void;
  focusDomain: string | null;
  sourceLabel: string | null;
}) {
  const count = unmanaged.toLocaleString();
  const subject = focusDomain ? "it" : "them";
  const redeploy = `Add ${sourceLabel ?? "their source"} as a deployment target to redeploy automatically.`;
  return (
    <Alert variant={expiring > 0 ? "warning" : "info"}>
      <ShieldWarningIcon aria-hidden />
      <AlertTitle>
        {expiring > 0
          ? `${expiring.toLocaleString()} certificate${expiring === 1 ? "" : "s"} outside CertPing ${expiring === 1 ? "expires" : "expire"} within 30 days`
          : `${count} certificate${unmanaged === 1 ? " is" : "s are"} renewed outside CertPing`}
      </AlertTitle>
      <AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>
          {expiring > 0
            ? `${focusDomain ? "It is" : "They are"} among ${count} certificates CertPing isn't renewing. `
            : ""}
          {`Reissue ${subject} through CertPing and ${focusDomain ? "it renews" : "they renew"} on ${focusDomain ? "its" : "their"} own. ${redeploy}`}
        </span>
        <span className="flex shrink-0 gap-2">
          {onReview ? (
            <Button
              variant={canIssue && !focusDomain ? "default" : "outline"}
              size="sm"
              onClick={onReview}
            >
              {focusDomain
                ? "Show it"
                : expiring > 0
                  ? "Show expiring"
                  : "Show them"}
            </Button>
          ) : null}
          {canIssue && focusDomain ? (
            <Button size="sm" asChild>
              <Link href={issueCertificateHref({ domain: focusDomain })}>
                Issue with CertPing
              </Link>
            </Button>
          ) : null}
        </span>
      </AlertDescription>
    </Alert>
  );
}

export function ProviderCoverage({
  certificates,
  isLoading = false,
  selectedTargetType,
  onSelectTargetType,
  onFocusUnmanaged,
  onFocusExpiring,
  onFocusUnmanagedExpiring,
  canIssue = false,
}: {
  certificates: DiscoveredCert[];
  isLoading?: boolean;
  selectedTargetType?: string;
  onSelectTargetType: (targetType: string | undefined) => void;
  onFocusUnmanaged?: () => void;
  onFocusExpiring?: () => void;
  onFocusUnmanagedExpiring?: () => void;
  canIssue?: boolean;
}) {
  const [detailsOpen, setDetailsOpen] = React.useState(false);
  const summaries = DISCOVERY_SOURCE_OPTIONS.map((source) => {
    const sourceCertificates = certificates.filter(
      (cert) => cert.targetType === source.value,
    );
    return {
      ...source,
      count: sourceCertificates.length,
      unmanagedCount: sourceCertificates.filter(isUnmanagedDiscoveredCert)
        .length,
      expiringSoonCount: sourceCertificates.filter((cert) =>
        isExpiringWithinDays(cert.notAfter, 30),
      ).length,
      expiredCount: sourceCertificates.filter((cert) =>
        isExpiredAt(cert.notAfter),
      ).length,
    };
  });
  const unmanagedCount = certificates.filter(isUnmanagedDiscoveredCert).length;
  const expiringSoonCount = certificates.filter((cert) =>
    isExpiringWithinDays(cert.notAfter, 30),
  ).length;
  const unmanagedExpiring = certificates.filter(
    (cert) =>
      isUnmanagedDiscoveredCert(cert) &&
      isExpiringWithinDays(cert.notAfter, 30),
  );
  const unmanagedExpiringCount = unmanagedExpiring.length;
  const calloutSet =
    unmanagedExpiringCount > 0
      ? unmanagedExpiring
      : certificates.filter(isUnmanagedDiscoveredCert);
  const focusDomain =
    calloutSet.length === 1 ? (calloutSet[0].domain ?? null) : null;
  const calloutTargetType = calloutSet[0]?.targetType;
  const calloutSourceLabel =
    calloutTargetType &&
    calloutSet.every((cert) => cert.targetType === calloutTargetType)
      ? formatDiscoveryTargetLabel(calloutTargetType)
      : null;
  const activeSourceCount = summaries.filter(
    (summary) => summary.count > 0,
  ).length;
  const selectedSourceLabel = selectedTargetType
    ? summaries.find((summary) => summary.value === selectedTargetType)?.label
    : null;

  return (
    <>
      {!isLoading && unmanagedCount > 0 ? (
        <UnmanagedCallout
          unmanaged={unmanagedCount}
          expiring={unmanagedExpiringCount}
          canIssue={canIssue}
          focusDomain={focusDomain}
          sourceLabel={calloutSourceLabel}
          onReview={
            unmanagedExpiringCount > 0
              ? onFocusUnmanagedExpiring
              : onFocusUnmanaged
          }
        />
      ) : null}
      <MetricStrip aria-label="Discovery summary">
        <MetricCard
          title={selectedSourceLabel ? "discovered in total" : "discovered"}
          value={certificates.length}
          isLoading={isLoading}
          icon={BinocularsIcon}
        />
        <MetricCard
          title="not managed by CertPing"
          value={unmanagedCount}
          isLoading={isLoading}
          icon={ShieldWarningIcon}
          onClick={onFocusUnmanaged}
        />
        <MetricCard
          title="expire within 30 days"
          value={expiringSoonCount}
          isLoading={isLoading}
          icon={WarningIcon}
          tone="warning"
          onClick={onFocusExpiring}
        />
        <MetricCard
          title="sources"
          value={activeSourceCount}
          unit={`of ${summaries.length}`}
          isLoading={isLoading}
          icon={StackIcon}
          onClick={() => setDetailsOpen(true)}
        />
      </MetricStrip>

      <Dialog open={detailsOpen} onOpenChange={setDetailsOpen}>
        <DialogContent className="sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>Provider coverage</DialogTitle>
            <DialogDescription>
              Review source-level discovery coverage, then focus the inventory
              table on a provider.
            </DialogDescription>
          </DialogHeader>

          <div className="grid max-h-[68vh] gap-3 overflow-y-auto pr-1 md:grid-cols-2 xl:grid-cols-3">
            {summaries.map((summary) => {
              const isSelected = selectedTargetType === summary.value;
              return (
                <div
                  key={summary.value}
                  className={`rounded-md border bg-card p-4 ${
                    isSelected
                      ? "border-primary/40 bg-primary/5"
                      : "border-border"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex min-w-0 items-center gap-3">
                      <div className="flex size-10 shrink-0 items-center justify-center rounded-md border border-border bg-background">
                        <SourceLogo targetType={summary.value} size={24} />
                      </div>
                      <div className="min-w-0">
                        <h3 className="truncate text-sm font-semibold text-foreground">
                          {summary.label}
                        </h3>
                        <p className="text-xs text-muted-foreground">
                          {summary.count} certificates discovered
                        </p>
                      </div>
                    </div>
                    <Badge variant={isSelected ? "info" : "secondary"}>
                      {isSelected ? "Focused" : "Source"}
                    </Badge>
                  </div>

                  <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                    <div className="rounded-md border border-border bg-background p-2">
                      <div className="font-mono text-lg font-semibold">
                        {summary.count}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        total
                      </div>
                    </div>
                    <div className="rounded-md border border-border bg-background p-2">
                      <div className="font-mono text-lg font-semibold text-warning">
                        {summary.unmanagedCount}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        external
                      </div>
                    </div>
                    <div className="rounded-md border border-border bg-background p-2">
                      <div className="font-mono text-lg font-semibold text-destructive">
                        {summary.expiringSoonCount + summary.expiredCount}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        expiry
                      </div>
                    </div>
                  </div>

                  <Button
                    type="button"
                    variant={isSelected ? "default" : "outline"}
                    size="sm"
                    className="mt-4 w-full"
                    onClick={() => {
                      onSelectTargetType(
                        isSelected ? undefined : summary.value,
                      );
                      setDetailsOpen(false);
                    }}
                  >
                    <CrosshairIcon className="h-4 w-4" aria-hidden="true" />
                    {isSelected ? "Clear focus" : "Focus inventory"}
                  </Button>
                </div>
              );
            })}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

export function DiscoveryGrid({
  certificates,
  onSelect,
}: {
  certificates: DiscoveredCert[];
  onSelect?: (id: number) => void;
}) {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {certificates.map((cert) => {
        const sanCount = cert.sanDomains?.length ?? 0;
        const manageHref =
          cert.managed === true && cert.managedCertificateXref
            ? `/cert-manager/manage/${encodeURIComponent(cert.managedCertificateXref)}`
            : null;

        return (
          <article
            key={cert.id}
            className="group cursor-pointer rounded-md border border-border bg-card p-4 transition-colors focus-within:ring-2 focus-within:ring-brand hover:bg-muted"
            role="button"
            tabIndex={0}
            onClick={() => onSelect?.(cert.id)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onSelect?.(cert.id);
              }
            }}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                {manageHref ? (
                  <Link
                    href={manageHref}
                    className="block truncate text-sm font-semibold text-primary hover:underline"
                    title={`View managed certificate for ${cert.domain ?? "this certificate"}`}
                    onClick={(event) => event.stopPropagation()}
                  >
                    {cert.domain ?? "Unknown domain"}
                  </Link>
                ) : (
                  <h2
                    className="truncate text-sm font-semibold text-foreground"
                    title={cert.domain ?? undefined}
                  >
                    {cert.domain ?? "Unknown domain"}
                  </h2>
                )}
                <p className="mt-1 text-xs text-muted-foreground">
                  {sanCount} SAN {sanCount === 1 ? "entry" : "entries"}
                </p>
              </div>
              <Badge variant={getCertStatusBadgeVariant(cert.certStatus)}>
                {humanizeEnum(cert.certStatus) || "Unknown"}
              </Badge>
            </div>

            <div className="mt-4 rounded-md border border-border bg-background p-3">
              <SourceSummary cert={cert} />
            </div>

            <dl className="mt-4 space-y-3 text-sm">
              <div className="flex items-center justify-between gap-3">
                <dt className="text-muted-foreground">Key</dt>
                <dd className="truncate text-right font-medium text-foreground">
                  {cert.keyAlgorithm ?? "Unknown"}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-muted-foreground">Management</dt>
                <dd>
                  <Badge variant={getManagedBadgeVariant(cert.managed)}>
                    {getManagedLabel(cert.managed)}
                  </Badge>
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-muted-foreground">Issued on</dt>
                <dd className="font-medium text-foreground">
                  {cert.notBefore ? formatDate(cert.notBefore) : "-"}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-muted-foreground">Expires on</dt>
                <dd>
                  <Badge variant={getExpiryBadgeVariant(cert.notAfter)}>
                    {cert.notAfter ? formatDate(cert.notAfter) : "-"}
                  </Badge>
                </dd>
              </div>
            </dl>

            <div className="mt-4 flex items-center justify-between border-t border-border pt-3 text-xs text-muted-foreground">
              <span>Discovered {formatDate(cert.discoveredAt)}</span>
              <span className="inline-flex items-center gap-1 font-medium text-primary">
                Open details
                <ArrowRightIcon className="h-3.5 w-3.5" aria-hidden="true" />
              </span>
            </div>
          </article>
        );
      })}
    </div>
  );
}
