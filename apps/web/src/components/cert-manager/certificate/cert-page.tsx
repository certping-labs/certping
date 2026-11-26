// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  CaretRightIcon,
  ArrowCounterClockwiseIcon,
  DownloadSimpleIcon,
  ShieldIcon,
  TrashIcon,
} from "@phosphor-icons/react";

import { useAuth } from "@/hooks/use-auth";
import { useCanDownloadCertificates } from "@/hooks/certificate-download-access";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import {
  useCompleteDnsChallenge,
  useDeletePendingSSLCertificate,
  useGetTxtRecords,
  useRenewCertificate,
  useRevokeCertificate,
} from "@/hooks/ssl";
import {
  canCreateDeployments,
  canExportPrivateKey,
  canDeleteCertificates,
  canRenewCertificates,
  canRevokeCertificates,
  canUpdateCredentials,
} from "@/lib/authz";
import {
  formatCertDate,
  getRemainingDays,
  getValidFrom,
  getValidTo,
} from "@/lib/utils";
import {
  canConvertManualCertificateToAutomated,
  getCertificateManagementState,
} from "@/lib/certificate-management";
import { isCertificateExportAvailable } from "@/lib/cert-manager/certificate-export-availability";
import type { CertificateDownloadTarget } from "@/types/certificate-export";
import type { SSLCertificateDetails } from "@/types/ssl";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CertDetailss } from "./cert-details";
import { CertDeployments } from "./cert-deployments";
import { CertHistory } from "./cert-history";
import {
  CertificateManagementDialog,
  CertificateManagementSummaryCard,
} from "@/components/cert-manager/certificate-management-dialog";
import { DeployNewCertDialog } from "@/components/cert-manager/deploy-new-cert-dialog";
import {
  LazyDownloadCertificateDialog,
  preloadDownloadCertificateDialog,
} from "@/components/cert-manager/certificate-download/lazy-download-certificate-dialog";
import {
  ManualTxtRecordsDialog,
  type ManualTxtRecordsDialogState,
} from "@/components/cert-manager/manual-txt-records-dialog";
import {
  canConfigureCertificateAutomation,
  canDeployCertificateRecord,
  isActiveLikeCertificateStatus,
  canManageManualDns as canManageManualDnsRecord,
  canRenewCertificateRecord,
  canRequestCertificateAgain,
  canRevokeCertificateRecord,
} from "@/lib/cert-manager/certificates-page-helpers";
import { requestAgainHref } from "@/lib/cert-manager/key-custody";
import {
  getCertificateStatusLabel,
  getCertificateStatusTone,
} from "@/lib/cert-manager/certificate-status";

interface CertificateDetailsProps {
  certificate: SSLCertificateDetails;
}

type CertificateTab = "details" | "deployment" | "history";

type DeploymentFocus = {
  certificateXref: string;
  status?: string;
} | null;

const DELETABLE_CERTIFICATE_STATUSES = new Set([
  "PENDING",
  "PENDING_DNS",
  "AWAITING_DNS",
  "FAILED",
  "REVOKED",
  "EXPIRED",
]);

const ONE_DAY_MS = 24 * 60 * 60 * 1000;

/** True for a certificate issued in the last day: the download prompt is for a fresh issuance, not for ever. */
function isIssuedWithinADay(validFrom: string | null | undefined): boolean {
  if (!validFrom) {
    return false;
  }
  const issuedAt = Date.parse(validFrom);
  return Number.isFinite(issuedAt) && Date.now() - issuedAt < ONE_DAY_MS;
}

export function CertificateDetails({ certificate }: CertificateDetailsProps) {
  const router = useRouter();
  const { user } = useAuth();
  const isCertRenewalEnabled = useIsFeatureEnabled("CERTIFICATE_RENEWAL");
  const isCertRevocationEnabled = useIsFeatureEnabled("CERTIFICATE_REVOCATION");
  const isCertDeploymentEnabled = useIsFeatureEnabled("CERTIFICATE_DEPLOYMENT");
  const [activeTab, setActiveTab] = useState<CertificateTab>("details");
  const [pendingAction, setPendingAction] = useState<
    null | "revoke" | "delete"
  >(null);
  const [managementDialogOpen, setManagementDialogOpen] = useState(false);
  const [manualDnsDraft, setManualDnsDraft] =
    useState<ManualTxtRecordsDialogState | null>(null);
  const [deploymentFocus, setDeploymentFocus] = useState<DeploymentFocus>(null);
  const [deployDialogOpen, setDeployDialogOpen] = useState(false);
  // The target is captured when the dialog opens: a refetch that withdraws
  // availability (say after a 410) must not unmount the dialog showing why.
  const [openDownloadTarget, setOpenDownloadTarget] =
    useState<CertificateDownloadTarget | null>(null);
  const canDownloadCertificates = useCanDownloadCertificates();
  // Losing access (say a 423) unmounts the dialog; drop its target too so
  // regaining access later in the session does not reopen it unasked.
  const [prevCanDownload, setPrevCanDownload] = useState(
    canDownloadCertificates,
  );
  if (canDownloadCertificates !== prevCanDownload) {
    setPrevCanDownload(canDownloadCertificates);
    if (!canDownloadCertificates) setOpenDownloadTarget(null);
  }

  const renewCertificate = useRenewCertificate();
  const revokeCertificate = useRevokeCertificate();
  const deleteCertificate = useDeletePendingSSLCertificate();
  const getTxtRecords = useGetTxtRecords();
  const validateDns = useCompleteDnsChallenge();

  const canDeploy = canCreateDeployments(user);
  const canDownloadPrivateKey = canExportPrivateKey(user);
  const canRenew = canRenewCertificates(user);
  const canRevoke = canRevokeCertificates(user);
  const canDelete = canDeleteCertificates(user);
  // The automation dialog holds renewal settings, so it is offered only while renewal is on.
  const canManageCredentialConfig =
    isCertRenewalEnabled &&
    canUpdateCredentials(user) &&
    canConfigureCertificateAutomation(certificate);
  const managementState = getCertificateManagementState(certificate);
  const automationActionLabel = canConvertManualCertificateToAutomated(
    certificate,
  )
    ? "Enable automation"
    : "Manage automation";

  const validFrom = getValidFrom(certificate);
  const validTo = getValidTo(certificate);
  const remainingDays = getRemainingDays(validTo);
  const activeDeploymentCertificateXref = useMemo(
    () => deploymentFocus?.certificateXref || certificate.certificateXref,
    [certificate.certificateXref, deploymentFocus?.certificateXref],
  );
  const canShowDeployAction =
    isCertDeploymentEnabled &&
    canDeploy &&
    canDeployCertificateRecord(certificate);
  const canShowRenewAction =
    isCertRenewalEnabled &&
    canRenew &&
    Boolean(certificate.certificateXref) &&
    canRenewCertificateRecord(certificate);
  const canShowRequestAgainAction =
    canRenew &&
    Boolean(certificate.certificateXref) &&
    canRequestCertificateAgain(certificate);
  const canShowRevokeAction =
    isCertRevocationEnabled &&
    canRevoke &&
    canRevokeCertificateRecord(certificate);
  const canShowDeleteAction =
    canDelete &&
    Boolean(certificate.userDomainCertId) &&
    DELETABLE_CERTIFICATE_STATUSES.has(certificate.status.toUpperCase());
  const canManageManualDns =
    managementState === "manual" && canManageManualDnsRecord(certificate);
  const downloadTarget: CertificateDownloadTarget | null =
    canDownloadCertificates &&
    certificate.certificateXref &&
    isCertificateExportAvailable(certificate.export)
      ? {
          certificateXref: certificate.certificateXref,
          domain: certificate.domain,
          isWildcard: certificate.wildcard === true,
          formats: certificate.export.formats,
          keyCustody: certificate.keyCustody,
        }
      : null;
  const isReadyToDownload =
    downloadTarget !== null &&
    certificate.status.toUpperCase() === "ACTIVE" &&
    isIssuedWithinADay(validFrom);
  const isManualDnsPreparing =
    Boolean(certificate.certificateXref) &&
    managementState === "manual" &&
    certificate.status === "PENDING_DNS";
  return (
    <>
      <AlertDialog
        open={Boolean(pendingAction)}
        onOpenChange={(open) => {
          if (!open) {
            setPendingAction(null);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {pendingAction === "delete"
                ? "Delete certificate?"
                : "Revoke certificate?"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {pendingAction === "delete"
                ? "This removes the certificate record from the active UI. Existing deployed copies are not cleaned up automatically."
                : "This starts the revoke workflow and the certificate will move into a revoking state while the backend processes it."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={async () => {
                if (!pendingAction) {
                  return;
                }

                if (pendingAction === "delete") {
                  if (!certificate.userDomainCertId) {
                    return;
                  }

                  await deleteCertificate.mutateAsync({
                    userDomainCertId: certificate.userDomainCertId,
                  });
                  router.push("/cert-manager");
                  return;
                }

                if (!certificate.certificateXref) {
                  return;
                }

                await revokeCertificate.mutateAsync({
                  certificateXref: certificate.certificateXref,
                });
                setPendingAction(null);
              }}
            >
              Confirm
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <CertificateManagementDialog
        certificate={certificate}
        open={managementDialogOpen}
        onOpenChange={setManagementDialogOpen}
      />
      <DeployNewCertDialog
        open={deployDialogOpen}
        onOpenChange={setDeployDialogOpen}
        initialCertificateId={certificate.certificateXref || undefined}
      />

      {canDownloadCertificates && openDownloadTarget ? (
        <LazyDownloadCertificateDialog
          target={openDownloadTarget}
          canDownloadPrivateKey={canDownloadPrivateKey}
          onClose={() => setOpenDownloadTarget(null)}
        />
      ) : null}

      <ManualTxtRecordsDialog
        draft={manualDnsDraft}
        open={Boolean(manualDnsDraft)}
        isValidating={validateDns.isPending}
        onOpenChange={(open) => {
          if (!open) {
            setManualDnsDraft(null);
          }
        }}
        onValidate={async (draft) => {
          await validateDns.mutateAsync({
            certificateXref: draft.certificateXref,
          });
          setManualDnsDraft(null);
        }}
      />

      <div className="space-y-6">
        <div className="flex items-center gap-2 text-sm">
          <Link
            href="/cert-manager"
            className="text-muted-foreground hover:text-foreground"
          >
            Certificate Manager
          </Link>
          <CaretRightIcon className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium text-foreground">
            {certificate.domain}
          </span>
        </div>

        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-bold">{certificate.domain}</h1>
              <Badge
                variant={getCertificateStatusTone(certificate.status)}
                className="px-3 py-1"
              >
                {getCertificateStatusLabel(certificate.status)}
              </Badge>
            </div>
            {isActiveLikeCertificateStatus(certificate.status) &&
            validFrom &&
            validTo ? (
              <div className="mt-2 text-sm text-muted-foreground">
                Valid {formatCertDate(validFrom)} to {formatCertDate(validTo)}
                {remainingDays != null
                  ? ` • ${remainingDays} days remaining`
                  : ""}
              </div>
            ) : null}
          </div>

          <div className="flex flex-wrap gap-2">
            {canShowRenewAction ? (
              <Button
                variant="outline"
                onClick={() =>
                  renewCertificate.mutate({
                    certificateXref: certificate.certificateXref || "",
                  })
                }
                isPending={renewCertificate.isPending}
              >
                {!renewCertificate.isPending && (
                  <ArrowCounterClockwiseIcon className="h-4 w-4" />
                )}
                Renew
              </Button>
            ) : null}
            {canShowRequestAgainAction && certificate.certificateXref ? (
              <Button asChild variant="outline">
                <Link href={requestAgainHref(certificate.certificateXref)}>
                  <ArrowCounterClockwiseIcon className="h-4 w-4" />
                  Request again
                </Link>
              </Button>
            ) : null}
            {canShowDeployAction && certificate.certificateXref ? (
              <Button
                variant="outline"
                onClick={() => setDeployDialogOpen(true)}
              >
                Deploy
              </Button>
            ) : null}
            {downloadTarget ? (
              <Button
                variant="outline"
                onClick={() => setOpenDownloadTarget(downloadTarget)}
                onPointerEnter={preloadDownloadCertificateDialog}
                onFocus={preloadDownloadCertificateDialog}
              >
                <DownloadSimpleIcon className="h-4 w-4" aria-hidden />
                Download
              </Button>
            ) : null}
            {canManageManualDns ? (
              <Button
                variant="outline"
                onClick={async () => {
                  const txtRecords = await getTxtRecords.mutateAsync({
                    certificateXref: certificate.certificateXref || "",
                  });
                  setManualDnsDraft({
                    certificateXref: certificate.certificateXref || "",
                    domain: certificate.domain,
                    txtRecords,
                  });
                }}
              >
                View TXT records
              </Button>
            ) : null}
            {canShowRevokeAction ? (
              <Button
                variant="destructive"
                onClick={() => setPendingAction("revoke")}
              >
                Revoke
              </Button>
            ) : null}
            {canShowDeleteAction ? (
              <Button
                variant="destructive"
                onClick={() => setPendingAction("delete")}
              >
                <TrashIcon className="size-4" />
                Delete
              </Button>
            ) : null}
          </div>
        </div>

        {certificate.userMessage &&
        certificate.status?.toUpperCase() !== "FAILED" ? (
          <Alert variant="destructive">
            <ShieldIcon aria-hidden />
            <AlertDescription>{certificate.userMessage}</AlertDescription>
          </Alert>
        ) : null}

        {isReadyToDownload && downloadTarget ? (
          <Alert variant="success">
            <DownloadSimpleIcon aria-hidden />
            <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
              <span>
                Your certificate is ready. Download it to install it on your
                server
                {certificate.keyCustody === "CUSTOMER_HELD"
                  ? ", together with the private key you saved when you requested it"
                  : ""}
                .
              </span>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setOpenDownloadTarget(downloadTarget)}
                onPointerEnter={preloadDownloadCertificateDialog}
                onFocus={preloadDownloadCertificateDialog}
              >
                Download
              </Button>
            </AlertDescription>
          </Alert>
        ) : null}

        {canManageManualDns ? (
          <Alert variant="warning">
            <AlertDescription>
              Waiting for DNS validation. Open the TXT records, publish them at
              your DNS provider, then select Validate DNS.
            </AlertDescription>
          </Alert>
        ) : null}

        {isManualDnsPreparing ? (
          <Alert>
            <ShieldIcon className="h-4 w-4" />
            <AlertDescription>
              Manual issuance is still preparing DNS instructions. This page is
              polling automatically and will expose TXT record actions once the
              status moves to awaiting DNS.
            </AlertDescription>
          </Alert>
        ) : null}

        <Tabs
          value={activeTab}
          onValueChange={(value) => setActiveTab(value as CertificateTab)}
          className="space-y-6"
        >
          <TabsList variant="underline">
            <TabsTrigger value="details">Details</TabsTrigger>
            {isCertDeploymentEnabled && (
              <TabsTrigger value="deployment">Deployments</TabsTrigger>
            )}
            <TabsTrigger value="history">Lifecycle</TabsTrigger>
          </TabsList>

          <TabsContent value="details" className="mt-0">
            <div className="space-y-6">
              <CertificateManagementSummaryCard
                certificate={certificate}
                canManage={canManageCredentialConfig}
                onManage={() => setManagementDialogOpen(true)}
                actionLabel={automationActionLabel}
              />
              <CertDetailss certificate={certificate} />
            </div>
          </TabsContent>

          {isCertDeploymentEnabled && (
            <TabsContent value="deployment" className="mt-0">
              <CertDeployments
                certificate={certificate}
                canDeploy={canDeploy}
                canDeployCurrentCert={canShowDeployAction}
                onDeploy={() => setDeployDialogOpen(true)}
                selectedCertificateXref={activeDeploymentCertificateXref}
                selectedCertificateStatus={deploymentFocus?.status}
                onResetSelection={() => setDeploymentFocus(null)}
              />
            </TabsContent>
          )}

          <TabsContent value="history" className="mt-0">
            <CertHistory certificate={certificate} />
          </TabsContent>
        </Tabs>
      </div>
    </>
  );
}
