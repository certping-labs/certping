// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Link from "next/link";
import {
  ArrowClockwiseIcon,
  CloudArrowUpIcon,
  DownloadSimpleIcon,
  FileIcon,
  GearSixIcon,
  ProhibitIcon,
  ScrollIcon,
  TrashIcon,
} from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { RowActionsTrigger } from "@/components/ui/row-actions-trigger";
import { preloadDownloadCertificateDialog } from "@/components/cert-manager/certificate-download/lazy-download-certificate-dialog";
import {
  canConfigureCertificateAutomation,
  canDeleteCertificateRecord,
  canDeployCertificateRecord,
  canManageManualDns,
  canRenewCertificateRecord,
  canRequestCertificateAgain,
  canRevokeCertificateRecord,
  canViewCertificateDetails,
  getAutomationActionLabel,
  getCertificateDetailHref,
} from "@/lib/cert-manager/certificates-page-helpers";
import { requestAgainHref } from "@/lib/cert-manager/key-custody";
import { getRemainingDays } from "@/lib/utils";
import type { SSLCertificateListItem } from "@/types/ssl";

function isExpiringSoon(certificate: SSLCertificateListItem): boolean {
  const days = getRemainingDays(certificate.validTo ?? null);
  return days !== null && days <= 30;
}

function CertificatePrimaryAction({
  certificate,
  canRenew,
  canManageManualDns,
  onRenew,
  onOpenManualDns,
}: {
  certificate: SSLCertificateListItem;
  canRenew: boolean;
  canManageManualDns: boolean;
  onRenew: () => void;
  onOpenManualDns: () => void;
}) {
  const status = certificate.status?.toUpperCase();
  if (status === "FAILED" && canViewCertificateDetails(certificate)) {
    return (
      <Button
        asChild
        variant="soft"
        size="sm"
        className="hidden md:inline-flex"
      >
        <Link href={getCertificateDetailHref(certificate)}>
          See why it failed
        </Link>
      </Button>
    );
  }
  if (canManageManualDns) {
    return (
      <Button
        variant="soft"
        size="sm"
        className="hidden md:inline-flex"
        onClick={onOpenManualDns}
      >
        Add TXT records
      </Button>
    );
  }
  if (canRenew) {
    return (
      <Button size="sm" className="hidden md:inline-flex" onClick={onRenew}>
        Renew now
      </Button>
    );
  }
  return null;
}

export function CertificateActions({
  certificate,
  canDelete,
  canDeploy,
  canManageCredentialConfig,
  canRenew,
  canRevoke,
  isCertRenewalEnabled,
  isCertRevocationEnabled,
  onOpenManualDns,
  onManageCredentialConfig,
  onDelete,
  onRenew,
  onRevoke,
  onDownload,
}: {
  certificate: SSLCertificateListItem;
  canDelete: boolean;
  canDeploy: boolean;
  canManageCredentialConfig: boolean;
  canRenew: boolean;
  canRevoke: boolean;
  isCertRenewalEnabled: boolean;
  isCertRevocationEnabled: boolean;
  onOpenManualDns: (certificate: SSLCertificateListItem) => void;
  onManageCredentialConfig: (certificate: SSLCertificateListItem) => void;
  onDelete: (certificate: SSLCertificateListItem) => void;
  onRenew: (certificateXref: string) => void;
  onRevoke: (certificate: SSLCertificateListItem) => void;
  /** Present only when the user may download certificates at all. */
  onDownload?: (certificate: SSLCertificateListItem) => void;
}) {
  const certificateXref = certificate.certificateXref;
  const resolvedCertificateXref = certificateXref ?? "";
  // The same rule bulk delete uses: deleting goes by the managed domain's id,
  // not the certificate xref, so a row without an xref can still be deleted.
  const canDeleteRecord = canDelete && canDeleteCertificateRecord(certificate);
  const canDeployRecord =
    canDeploy &&
    Boolean(certificateXref) &&
    canDeployCertificateRecord(certificate);
  const canRenewRecord =
    isCertRenewalEnabled &&
    canRenew &&
    Boolean(certificateXref) &&
    canRenewCertificateRecord(certificate);
  const canRequestAgainRecord =
    canRenew &&
    Boolean(certificateXref) &&
    canRequestCertificateAgain(certificate);
  const canRevokeRecord =
    isCertRevocationEnabled &&
    canRevoke &&
    Boolean(certificateXref) &&
    canRevokeCertificateRecord(certificate);
  // The automation dialog holds renewal settings, so it is offered only while renewal is on.
  const canManageRecord =
    isCertRenewalEnabled &&
    canManageCredentialConfig &&
    canConfigureCertificateAutomation(certificate);
  const canManageManualDnsRecord = canManageManualDns(certificate);
  const canDownloadRecord =
    Boolean(onDownload) &&
    Boolean(certificateXref) &&
    certificate.exportAvailable === true;
  const hasDangerActions = canDeleteRecord || canRevokeRecord;

  return (
    <div className="flex items-center justify-end gap-1.5">
      <CertificatePrimaryAction
        certificate={certificate}
        canRenew={canRenewRecord && isExpiringSoon(certificate)}
        canManageManualDns={canManageManualDnsRecord}
        onRenew={() => onRenew(resolvedCertificateXref)}
        onOpenManualDns={() => onOpenManualDns(certificate)}
      />
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <RowActionsTrigger label={certificate.domain} />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          {canViewCertificateDetails(certificate) ? (
            <DropdownMenuItem asChild>
              <Link
                href={getCertificateDetailHref(certificate)}
                className="flex items-center gap-2"
              >
                <ScrollIcon className="h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
          ) : null}
          {canDeployRecord ? (
            <DropdownMenuItem asChild>
              <Link
                href={`/cert-manager/deployments?deployCertificateXref=${encodeURIComponent(
                  resolvedCertificateXref,
                )}`}
                className="flex items-center gap-2"
              >
                <CloudArrowUpIcon className="h-4 w-4 text-primary" />
                Deploy certificate
              </Link>
            </DropdownMenuItem>
          ) : null}
          {canDownloadRecord ? (
            <DropdownMenuItem
              onClick={() => onDownload?.(certificate)}
              onFocus={preloadDownloadCertificateDialog}
              className="flex items-center gap-2"
            >
              <DownloadSimpleIcon className="h-4 w-4" aria-hidden />
              Download
            </DropdownMenuItem>
          ) : null}
          {canRenewRecord ? (
            <DropdownMenuItem
              onClick={() => onRenew(resolvedCertificateXref)}
              className="flex items-center gap-2"
            >
              <ArrowClockwiseIcon className="h-4 w-4 text-[hsl(var(--success))]" />
              Renew certificate
            </DropdownMenuItem>
          ) : null}
          {canRequestAgainRecord ? (
            <DropdownMenuItem asChild>
              <Link
                href={requestAgainHref(resolvedCertificateXref)}
                className="flex items-center gap-2"
              >
                <ArrowClockwiseIcon className="h-4 w-4 text-[hsl(var(--success))]" />
                Request again
              </Link>
            </DropdownMenuItem>
          ) : null}
          {canManageRecord ? (
            <DropdownMenuItem
              onClick={() => onManageCredentialConfig(certificate)}
              className="flex items-center gap-2"
            >
              <GearSixIcon className="h-4 w-4 text-muted-foreground" />
              {getAutomationActionLabel(certificate)}
            </DropdownMenuItem>
          ) : null}
          {canManageManualDnsRecord ? (
            <DropdownMenuItem
              onClick={() => onOpenManualDns(certificate)}
              className="flex items-center gap-2"
            >
              <FileIcon className="h-4 w-4 text-[hsl(var(--warning-700))]" />
              View TXT records
            </DropdownMenuItem>
          ) : null}
          {hasDangerActions ? <DropdownMenuSeparator /> : null}
          {canRevokeRecord ? (
            <DropdownMenuItem
              onClick={() => onRevoke(certificate)}
              className="flex items-center gap-2"
            >
              <ProhibitIcon className="h-4 w-4 text-[hsl(var(--danger))]" />
              Revoke certificate
            </DropdownMenuItem>
          ) : null}
          {canDeleteRecord ? (
            <DropdownMenuItem
              className="flex items-center gap-2 text-destructive focus:text-destructive"
              onClick={() => onDelete(certificate)}
            >
              <TrashIcon className="h-4 w-4 text-[hsl(var(--danger))]" />
              Delete certificate
            </DropdownMenuItem>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
