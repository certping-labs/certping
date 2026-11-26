// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/use-auth";
import { useListCertificates, useRenewCertificate } from "@/hooks/ssl";
import { canRenewCertificates, canViewCertificates } from "@/lib/authz";
import type { SSLCertificateListItem } from "@/types/ssl";

/** Certificates renew inside this window; it matches the renewal scheduler's lead time. */
export const DUE_SOON_DAYS = 30;

export type RotationFilter = "all" | "due" | "failed" | "manual";

export type RotationRow = {
  certificate: SSLCertificateListItem;
  daysLeft: number | null;
  automated: boolean;
  failed: boolean;
  inProgress: boolean;
  dueSoon: boolean;
};

const IN_PROGRESS = new Set([
  "RENEWING",
  "PENDING",
  "PENDING_DNS",
  "AWAITING_DNS",
  "VALIDATING",
]);
const RENEWABLE = new Set([
  "ACTIVE",
  "RENEW_SUCCESS",
  "RENEWAL_FAILED",
  "EXPIRED",
]);
const GONE = new Set(["REVOKED", "REVOKING", "DELETED", "CANCELLED_MANUAL"]);

function daysUntil(
  validTo: string | null | undefined,
  now: Date,
): number | null {
  if (!validTo) return null;
  const end = new Date(validTo).getTime();
  if (Number.isNaN(end)) return null;
  return Math.floor((end - now.getTime()) / 86_400_000);
}

/** One row per certificate the rotation view cares about: everything not revoked or deleted. */
export function toRotationRows(
  certificates: readonly SSLCertificateListItem[],
  now: Date = new Date(),
): RotationRow[] {
  return certificates
    .filter((c) => !GONE.has(c.status))
    .map((certificate) => {
      const daysLeft = daysUntil(certificate.validTo, now);
      const automated =
        certificate.managementState !== undefined &&
        certificate.managementState !== "manual";
      return {
        certificate,
        daysLeft,
        automated,
        failed:
          certificate.status === "RENEWAL_FAILED" ||
          certificate.status === "FAILED",
        inProgress: IN_PROGRESS.has(certificate.status),
        dueSoon: daysLeft !== null && daysLeft <= DUE_SOON_DAYS,
      };
    })
    .sort((a, b) => {
      if (a.failed !== b.failed) return a.failed ? -1 : 1;
      return (
        (a.daysLeft ?? Number.MAX_SAFE_INTEGER) -
        (b.daysLeft ?? Number.MAX_SAFE_INTEGER)
      );
    });
}

export function applyRotationFilter(
  rows: RotationRow[],
  filter: RotationFilter,
): RotationRow[] {
  switch (filter) {
    case "due":
      return rows.filter((r) => r.dueSoon);
    case "failed":
      return rows.filter((r) => r.failed);
    case "manual":
      return rows.filter((r) => !r.automated);
    default:
      return rows;
  }
}

function describeRow(row: RotationRow): string {
  if (row.inProgress) return "Renewal in progress";
  if (row.failed) return "Last renewal failed";
  if (row.daysLeft === null) return "No expiry recorded";
  if (row.daysLeft < 0) return `Expired ${Math.abs(row.daysLeft)} days ago`;
  if (row.daysLeft === 0) return "Expires today";
  return `Expires in ${row.daysLeft} days`;
}

function RowBadge({ row }: { row: RotationRow }) {
  if (row.inProgress) return <Badge variant="secondary">In progress</Badge>;
  if (row.failed) return <Badge variant="destructive">Failed</Badge>;
  if (row.daysLeft !== null && row.daysLeft < 0) {
    return <Badge variant="destructive">Expired</Badge>;
  }
  if (row.dueSoon) return <Badge variant="outline">Due soon</Badge>;
  return <Badge variant="secondary">Scheduled</Badge>;
}

const FILTERS: Array<{ value: RotationFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "due", label: `Due within ${DUE_SOON_DAYS} days` },
  { value: "failed", label: "Failed" },
  { value: "manual", label: "Manual (no automation)" },
];

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardDescription>{label}</CardDescription>
        <CardTitle className="text-2xl">{value}</CardTitle>
      </CardHeader>
    </Card>
  );
}

/**
 * Rotation: which certificates renew when, which renewals failed, and the
 * connections (CA accounts, DNS providers) that automated renewal needs.
 * "Renew now" queues the same renewal the certificate page offers, for users
 * with certificate:renew.
 */
export function RotationPage() {
  const { user, isLoading: isLoadingAuth } = useAuth();
  const canView = canViewCertificates(user);
  const canRenew = canRenewCertificates(user);
  const [filter, setFilter] = useState<RotationFilter>("all");
  const list = useListCertificates({ enabled: canView && !isLoadingAuth });
  const renew = useRenewCertificate();

  const rows = useMemo(() => toRotationRows(list.data ?? []), [list.data]);
  const visible = useMemo(
    () => applyRotationFilter(rows, filter),
    [rows, filter],
  );
  const automatedCount = rows.filter((r) => r.automated).length;
  const dueCount = rows.filter((r) => r.dueSoon).length;
  const failedCount = rows.filter((r) => r.failed).length;

  if (!isLoadingAuth && !canView) {
    return (
      <div className="space-y-4">
        <PageHeader title="Rotation" />
        <p className="text-sm text-muted-foreground">
          You do not have access to certificate rotation.
        </p>
      </div>
    );
  }

  const loaded = Boolean(list.data);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Rotation"
        subtitle="Automated renewal: what renews when, what failed, and the connections it depends on."
      />

      <div className="grid gap-4 md:grid-cols-3">
        <Metric
          label="Automated certificates"
          value={
            loaded ? (
              `${automatedCount} of ${rows.length}`
            ) : (
              <Skeleton className="h-7 w-16" />
            )
          }
        />
        <Metric
          label={`Due within ${DUE_SOON_DAYS} days`}
          value={loaded ? dueCount : <Skeleton className="h-7 w-10" />}
        />
        <Metric
          label="Failed renewals"
          value={loaded ? failedCount : <Skeleton className="h-7 w-10" />}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Connections renewal depends on
          </CardTitle>
          <CardDescription>
            A certificate renews automatically when CertPing has a CA account to
            order from and, for DNS validation, a DNS provider credential for
            its zone. Both are configured under Integrations.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button asChild variant="outline" size="sm">
            <Link href="/integrations/certificate-authorities">
              Certificate authorities
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/integrations/dns">DNS providers</Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href="/integrations/deployment-targets">
              Deployment targets
            </Link>
          </Button>
        </CardContent>
      </Card>

      <section aria-labelledby="rotation-schedule" className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 id="rotation-schedule" className="text-lg font-semibold">
            Renewal schedule
          </h2>
          <div
            role="group"
            aria-label="Filter renewals"
            className="flex flex-wrap gap-1"
          >
            {FILTERS.map((f) => (
              <Button
                key={f.value}
                size="sm"
                variant={filter === f.value ? "default" : "ghost"}
                aria-pressed={filter === f.value}
                onClick={() => setFilter(f.value)}
              >
                {f.label}
              </Button>
            ))}
          </div>
        </div>

        {list.isLoading ? (
          <Skeleton className="h-32 w-full" data-testid="rotation-loading" />
        ) : visible.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {rows.length === 0
              ? "No certificates yet. Issue or discover certificates and their renewals show up here."
              : "Nothing matches this filter."}
          </p>
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50 text-left">
                <tr>
                  <th className="px-3 py-2 font-medium">Certificate</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Next renewal</th>
                  <th className="px-3 py-2 font-medium">CA</th>
                  <th className="px-3 py-2 font-medium">Automation</th>
                  <th className="px-3 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((row) => {
                  const c = row.certificate;
                  const key = c.certificateXref ?? `${c.domain}-${c.id ?? ""}`;
                  const renewable =
                    Boolean(c.certificateXref) &&
                    RENEWABLE.has(c.status) &&
                    !row.inProgress;
                  return (
                    <tr key={key} className="border-t">
                      <td className="px-3 py-2">
                        {c.certificateXref ? (
                          <Link
                            className="font-medium underline-offset-2 hover:underline"
                            href={`/cert-manager/manage/${c.certificateXref}`}
                          >
                            {c.domain}
                          </Link>
                        ) : (
                          <span className="font-medium">{c.domain}</span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <RowBadge row={row} />
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {describeRow(row)}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {c.caProvider ?? "Unknown"}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {row.automated ? "Automated" : "Manual"}
                      </td>
                      <td className="px-3 py-2 text-right">
                        {canRenew && renewable ? (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={renew.isPending}
                            onClick={() =>
                              renew.mutate({
                                certificateXref: c.certificateXref as string,
                              })
                            }
                          >
                            Renew now
                          </Button>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
