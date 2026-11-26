// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { use, useState } from "react";
import Link from "next/link";
import { BellRingingIcon, CircleNotchIcon } from "@phosphor-icons/react";

import { CaConnectorLabel } from "@/components/machine-identity/ca-connector-label";
import {
  DefinitionList,
  DetailEmptyState,
  DetailPanel,
  DetailRow,
  PanelMasonry,
} from "@/components/machine-identity/detail-panel";
import { DeviceEventList } from "@/components/machine-identity/device-event-list";
import { ModuleNotice } from "@/components/machine-identity/module-notice";
import { MachineIdentityQueryErrorState } from "@/components/machine-identity/query-error-state";
import { RevokeCertificateDialog } from "@/components/machine-identity/revoke-certificate-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useCertificate,
  useCertificateHistory,
  useRequestCertificateDeviceSync,
} from "@/hooks/machine-identity/use-machine-certificates";
import { useDeviceSource } from "@/hooks/machine-identity/use-device-sources";
import { useDevice } from "@/hooks/machine-identity/use-machine-devices";
import { usePermissions } from "@/hooks/use-permissions";
import {
  canRequestRevocation,
  CERTIFICATE_RENEWAL_STATE_LABELS,
  certificateRenewalStateVariant,
  certificateStatusLabel,
  certificateStatusVariant,
  extendedKeyUsageLabel,
  formatKeyStrength,
  formatRemainingLifetime,
  INTUNE_DEVICE_CHECK_IN_PERMISSION,
  isRevocationInFlight,
  NUDGE_OUTCOME_DESCRIPTIONS,
  nudgeOutcomeLabel,
  nudgeOutcomeVariant,
  sanTypeLabel,
} from "@/lib/machine-identity/backend-display";
import { PERMISSIONS } from "@/lib/authz";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { certificateCheckInUnavailableReason } from "@/lib/machine-identity/certificate-check-in";
import { cn, formatDateTimeCompact } from "@/lib/utils";
import type {
  DeviceSyncDeviceResult,
  DeviceSyncSkipReason,
} from "@/types/machine-identity-backend";

const CERTIFICATES_HREF = "/machine-identity/device-certificates";
const HISTORY_PAGE_SIZE = 25;

/**
 * Why the revoke button is off, as a tooltip. Mirrors the backend's own
 * refusals so the operator gets the reason on hover instead of a `422` after
 * filling the form in.
 */
function revocationBlockedReason(certificate: {
  status: string;
  caProvider: string;
  certificateAuthority: boolean;
}): string | undefined {
  if (certificate.certificateAuthority) {
    return "CA certificates cannot be revoked from this page.";
  }
  if (!["EJBCA", "SMALLSTEP"].includes(certificate.caProvider.toUpperCase())) {
    return `${certificate.caProvider} has no revocation path wired up in CertPing.`;
  }
  if (certificate.status === "REVOKED") {
    return "This certificate is already revoked.";
  }
  if (
    certificate.status === "REVOCATION_PENDING" ||
    certificate.status === "REVOCATION_DISPATCHED"
  ) {
    return "A revocation for this certificate is already in flight.";
  }
  return undefined;
}

/** Colour for a remaining-lifetime figure; expiry is the one number that must never read neutral. */
function lifetimeClassName(remainingDays: number): string | undefined {
  if (remainingDays < 0) return "status-danger-text";
  if (remainingDays <= 30) return "status-warning-text";
  return undefined;
}

const DEVICE_SYNC_SKIP_MESSAGES: Record<DeviceSyncSkipReason, string> = {
  DEVICE_NOT_FOUND: "The linked device no longer exists in CertPing.",
  UNSUPPORTED_OR_INACTIVE_SOURCE:
    "The device is not linked to an active Microsoft Intune source.",
  NO_MANAGED_DEVICE_ID:
    "The device does not have a valid Intune managed-device ID.",
  NO_CURRENT_CERTIFICATE:
    "The device has no current certificate that can be renewed.",
  OUTSIDE_RENEWAL_THRESHOLD:
    "No current certificate is inside its synced profile's renewal threshold.",
  PROFILE_THRESHOLD_UNAVAILABLE:
    "No current certificate has a synced profile renewal threshold.",
  COOLDOWN_ACTIVE:
    "A device check-in was requested recently and its cooldown is still active.",
};

function skippedCheckInMessage(result: DeviceSyncDeviceResult): string {
  if (!result.reason) return "The device was not eligible for check-in.";
  const message = DEVICE_SYNC_SKIP_MESSAGES[result.reason];
  if (result.reason === "COOLDOWN_ACTIVE" && result.nextAllowedAt) {
    return `${message} Try again after ${formatDateTimeCompact(result.nextAllowedAt)}.`;
  }
  return message;
}

export default function MachineCertificateDetailPage({
  params,
}: {
  params: Promise<{ certificateId: string }>;
}) {
  const { certificateId: certificateXref } = use(params);
  const [historyPage, setHistoryPage] = useState(0);

  const certificateQuery = useCertificate(certificateXref);
  const linkedDeviceXref = certificateQuery.data?.device?.deviceXref;
  const deviceQuery = useDevice(linkedDeviceXref, {
    enabled: Boolean(linkedDeviceXref),
  });
  const sourceXref = deviceQuery.data?.source.sourceXref;
  const sourceQuery = useDeviceSource(sourceXref, {
    enabled: Boolean(sourceXref),
  });
  const historyQuery = useCertificateHistory(certificateXref, {
    page: historyPage,
    size: HISTORY_PAGE_SIZE,
  });
  const requestCheckIn = useRequestCertificateDeviceSync();
  const { can } = usePermissions();

  if (certificateQuery.isLoading) {
    return (
      <div className="space-y-4 p-4 md:p-6">
        <Skeleton className="h-16 w-full max-w-xl" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (certificateQuery.error || !certificateQuery.data) {
    return (
      <div className="p-4 md:p-6">
        <MachineIdentityQueryErrorState
          error={certificateQuery.error}
          title="Unable to load certificate"
          description="This certificate could not be loaded."
          resourceLabel="certificate"
          backHref={CERTIFICATES_HREF}
          backLabel="Back to certificates"
          onRetry={() => void certificateQuery.refetch()}
          isRetrying={certificateQuery.isFetching}
        />
      </div>
    );
  }

  const certificate = certificateQuery.data;
  const enrollment = certificate.enrollment;
  const historyPageData = historyQuery.data;
  const device = deviceQuery.data;
  const source = sourceQuery.data;
  const checkInPermission = source?.health?.permissions.find(
    (permission) => permission.name === INTUNE_DEVICE_CHECK_IN_PERMISSION,
  );
  const checkInUnavailableReason = certificateCheckInUnavailableReason({
    canManage: can("iot_device:manage"),
    linkedDeviceXref,
    device,
    deviceLoading: deviceQuery.isLoading,
    deviceFailed: Boolean(deviceQuery.error),
    source,
    sourceLoading: sourceQuery.isLoading,
    sourceFailed: Boolean(sourceQuery.error),
  });
  const selectedCheckInResult = requestCheckIn.data?.devices.find(
    (result) => result.deviceXref === certificate.device?.deviceXref,
  );

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title={certificate.commonName}
        breadcrumbs={[
          { label: "Machine Identity" },
          { label: "Device certificates", href: CERTIFICATES_HREF },
        ]}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <CaConnectorLabel caProvider={certificate.caProvider} />
            {certificate.device ? (
              <>
                <span aria-hidden="true">·</span>
                <Link
                  href={`/machine-identity/devices/${certificate.device.deviceXref}`}
                  className="hover:text-foreground hover:underline"
                >
                  {certificate.device.deviceName ?? "Unnamed device"}
                </Link>
              </>
            ) : null}
            <span aria-hidden="true">·</span>
            <span className={cn(lifetimeClassName(certificate.remainingDays))}>
              {formatRemainingLifetime(certificate.remainingDays)}
            </span>
          </span>
        }
        badge={{
          label: certificateStatusLabel(certificate.status),
          variant: certificateStatusVariant(certificate.status),
        }}
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                certificate.device
                  ? requestCheckIn.mutate({
                      deviceXrefs: [certificate.device.deviceXref],
                    })
                  : undefined
              }
              disabled={
                Boolean(checkInUnavailableReason) || requestCheckIn.isPending
              }
              title={checkInUnavailableReason ?? undefined}
            >
              {requestCheckIn.isPending ? (
                <CircleNotchIcon
                  className="size-4 animate-spin"
                  aria-hidden="true"
                />
              ) : (
                <BellRingingIcon className="size-4" aria-hidden="true" />
              )}
              {requestCheckIn.isPending ? "Requesting" : "Request check-in"}
            </Button>
            {can(PERMISSIONS.iotDeviceManage) ? (
              <RevokeCertificateDialog
                certificateXref={certificate.certificateXref}
                commonName={certificate.commonName}
                deviceName={certificate.device?.deviceName ?? null}
                disabled={!canRequestRevocation(certificate)}
                disabledReason={revocationBlockedReason(certificate)}
              />
            ) : null}
          </>
        }
      />

      {isRevocationInFlight(certificate.status) ? (
        <ModuleNotice tone="info">
          The agent is submitting this revocation to {certificate.caProvider}.
          This page refreshes on its own until the CA confirms it.
        </ModuleNotice>
      ) : certificate.status === "REVOKED" ? (
        <ModuleNotice tone="info">
          This certificate is revoked. It stays in the inventory as the audit
          record of what was issued and withdrawn.
        </ModuleNotice>
      ) : certificate.status === "REVOCATION_FAILED" ? (
        <ModuleNotice tone="danger">
          The last revocation attempt failed at {certificate.caProvider}, so
          this certificate is still trusted. Check the history below, then
          request it again.
        </ModuleNotice>
      ) : certificate.status === "REVOCATION_OUTCOME_UNKNOWN" ? (
        <ModuleNotice tone="danger">
          CertPing reached {certificate.caProvider} but never got a
          confirmation, so it cannot say whether this certificate was revoked.
          Treat it as still trusted and verify against the CA directly.
        </ModuleNotice>
      ) : null}

      {selectedCheckInResult?.status === "QUEUED" ? (
        <ModuleNotice tone="info">
          Intune check-in queued for the linked device. Intune will notify the
          device; a new certificate appears after the device completes SCEP
          renewal.
        </ModuleNotice>
      ) : selectedCheckInResult?.status === "SKIPPED" ? (
        <ModuleNotice tone="warning">
          {skippedCheckInMessage(selectedCheckInResult)}
        </ModuleNotice>
      ) : null}

      {device?.source.provider === "INTUNE" &&
      source &&
      !checkInPermission?.granted ? (
        <ModuleNotice tone="warning">
          Manual device check-in is unavailable because the Intune connector has
          not reported the required privileged-operations permission.
        </ModuleNotice>
      ) : null}

      {certificate.status === "EXPIRED" ? (
        <ModuleNotice tone="danger">
          This certificate expired {formatDateTimeCompact(certificate.validTo)}.
          Any device still presenting it will fail authentication.
        </ModuleNotice>
      ) : certificate.status === "EXPIRING" ? (
        <ModuleNotice tone="warning">
          {formatRemainingLifetime(certificate.remainingDays)}. Renewal should
          already be under way on the device holding it.
        </ModuleNotice>
      ) : null}

      {certificate.device === null ? (
        <ModuleNotice tone="info">
          This certificate has not been correlated to a device in the registry.
          Certificates are recorded when the CA issues them, so a match can
          still arrive on a later device sync.
        </ModuleNotice>
      ) : null}

      <PanelMasonry>
        <DetailPanel title="Certificate">
          <dl className="divide-y divide-border">
            <DetailRow label="Common name" value={certificate.commonName} />
            <DetailRow
              label="Subject"
              value={certificate.subjectDn}
              monospace
              copyable
            />
            <DetailRow
              label="Serial number"
              value={certificate.serialNumber}
              monospace
              copyable
            />
            <DetailRow
              label="SHA-256 fingerprint"
              value={certificate.fingerprintSha256}
              monospace
              copyable
            />
            <DetailRow
              label="Issued"
              value={formatDateTimeCompact(certificate.issuedAt)}
            />
            <DetailRow
              label="Valid from"
              value={formatDateTimeCompact(certificate.validFrom)}
            />
            <DetailRow
              label="Valid to"
              value={formatDateTimeCompact(certificate.validTo)}
            />
            <DetailRow
              label="Remaining"
              node={
                <span
                  className={cn(lifetimeClassName(certificate.remainingDays))}
                >
                  {formatRemainingLifetime(certificate.remainingDays)}
                </span>
              }
            />
            {certificate.certificateAuthority ? (
              <DetailRow
                label="Basic constraints"
                node={<Badge variant="info">Certificate authority</Badge>}
              />
            ) : null}
          </dl>
        </DetailPanel>

        <DetailPanel title="Key material">
          <DefinitionList
            items={[
              { label: "Key", value: formatKeyStrength(certificate) },
              {
                label: "Signature algorithm",
                value: `${certificate.signatureAlgorithm} (${certificate.signatureAlgorithmOid})`,
                monospace: true,
              },
              {
                label: "Key usages",
                value: certificate.keyUsages.join(", ") || null,
              },
              {
                label: "Subject key identifier",
                value: certificate.subjectKeyIdentifier,
                monospace: true,
                copyable: true,
              },
              {
                label: "Authority key identifier",
                value: certificate.authorityKeyIdentifier,
                monospace: true,
                copyable: true,
              },
              {
                label: "Certificate policies",
                value: certificate.certificatePolicyOids.join(", ") || null,
                monospace: true,
              },
            ]}
          />
        </DetailPanel>

        <DetailPanel title="Subject alternative names">
          {certificate.subjectAlternativeNames.length === 0 ? (
            <DetailEmptyState message="This certificate carries no subject alternative names." />
          ) : (
            <ul className="divide-y divide-border">
              {certificate.subjectAlternativeNames.map((san, index) => (
                <li
                  key={`${san.type}-${san.value}-${index}`}
                  className="grid gap-x-3 gap-y-0.5 px-4 py-2 sm:grid-cols-[6rem_minmax(0,1fr)]"
                >
                  <span className="text-xs text-muted-foreground">
                    {sanTypeLabel(san.type)}
                  </span>
                  <span className="min-w-0 font-mono text-xs wrap-anywhere wrap-break-word">
                    {san.value}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </DetailPanel>

        <DetailPanel title="Binding">
          <dl className="divide-y divide-border">
            <DetailRow
              label="Device"
              node={
                certificate.device ? (
                  <Link
                    href={`/machine-identity/devices/${certificate.device.deviceXref}`}
                    className="hover:text-primary hover:underline"
                  >
                    {certificate.device.deviceName ?? "Unnamed device"}
                  </Link>
                ) : (
                  <span className="text-muted-foreground">
                    Not correlated to a device
                  </span>
                )
              }
            />
            <DetailRow
              label="CA"
              node={
                <span className="inline-flex flex-wrap items-center gap-1.5">
                  <CaConnectorLabel caProvider={certificate.caProvider} />
                  {certificate.caName ? (
                    <span className="text-muted-foreground">
                      · {certificate.caName}
                    </span>
                  ) : null}
                </span>
              }
            />
            <DetailRow
              label="Issuer DN"
              value={certificate.issuerDn}
              monospace
              copyable
            />
            <DetailRow
              label="CA end entity"
              value={certificate.caEndEntityName}
              monospace
            />
            <DetailRow
              label="CA provisioner"
              value={certificate.caProvisionerName}
              monospace
            />
            <DetailRow
              label="Certificate scope"
              value={
                certificate.certificateScope
                  ? humanizeConstant(certificate.certificateScope)
                  : null
              }
            />
            <DetailRow
              label="Profile"
              node={
                certificate.profile ? (
                  <Link
                    href={`/machine-identity/profiles/${certificate.profile.profileXref}`}
                    className="hover:text-primary hover:underline"
                  >
                    {certificate.profile.name}
                  </Link>
                ) : (
                  <span className="text-muted-foreground">
                    Not resolved to a profile
                  </span>
                )
              }
            />
          </dl>
        </DetailPanel>

        <DetailPanel title="Extended key usages">
          {certificate.extendedKeyUsageOids.length === 0 ? (
            <DetailEmptyState message="No extended key usages recorded." />
          ) : (
            <div className="space-y-2 px-4 py-3">
              {certificate.extendedKeyUsageOids.map((oid) => (
                <div
                  key={oid}
                  className="flex items-baseline justify-between gap-3"
                >
                  <span className="text-sm">{extendedKeyUsageLabel(oid)}</span>
                  <span className="font-mono text-xs text-muted-foreground">
                    {oid}
                  </span>
                </div>
              ))}
            </div>
          )}
        </DetailPanel>

        <DetailPanel title="Enrollment">
          {enrollment ? (
            <DefinitionList
              items={[
                {
                  label: "Type",
                  value: humanizeConstant(enrollment.enrollmentType),
                },
                {
                  label: "Status",
                  value: humanizeConstant(enrollment.status),
                },
                {
                  label: "Device match",
                  value: enrollment.deviceMatchStatus
                    ? humanizeConstant(enrollment.deviceMatchStatus)
                    : null,
                },
                {
                  label: "Profile resolution",
                  value: enrollment.profileResolutionStatus
                    ? humanizeConstant(enrollment.profileResolutionStatus)
                    : null,
                },
                {
                  label: "Transaction ID",
                  value: enrollment.transactionId,
                  monospace: true,
                  copyable: true,
                },
                {
                  label: "Prior serial",
                  value:
                    enrollment.priorCertificateSerialNumber ?? "First issuance",
                  monospace: true,
                },
                {
                  label: "Requested",
                  value: formatDateTimeCompact(enrollment.requestedAt),
                },
                {
                  label: "Validated",
                  value: enrollment.validatedAt
                    ? formatDateTimeCompact(enrollment.validatedAt)
                    : null,
                },
                {
                  label: "Completed",
                  value: enrollment.completedAt
                    ? formatDateTimeCompact(enrollment.completedAt)
                    : null,
                },
              ]}
            />
          ) : (
            <DetailEmptyState message="No enrollment record is linked to this certificate." />
          )}
        </DetailPanel>
        <DetailPanel title="Renewal">
          <dl className="divide-y divide-border">
            <DetailRow
              label="State"
              node={
                <Badge
                  variant={certificateRenewalStateVariant(
                    certificate.renewalState,
                  )}
                >
                  {CERTIFICATE_RENEWAL_STATE_LABELS[certificate.renewalState]}
                </Badge>
              }
            />
            <DetailRow
              label="Check-in attempts"
              value={String(certificate.nudgeAttempts)}
            />
            <DetailRow
              label="Last check-in"
              value={
                certificate.lastNudgedAt
                  ? formatDateTimeCompact(certificate.lastNudgedAt)
                  : "Never"
              }
            />
            <DetailRow
              label="Last outcome"
              node={
                certificate.lastNudgeOutcome ? (
                  <span className="flex min-w-0 flex-col items-start gap-1">
                    <Badge
                      variant={nudgeOutcomeVariant(
                        certificate.lastNudgeOutcome,
                      )}
                    >
                      {nudgeOutcomeLabel(certificate.lastNudgeOutcome)}
                    </Badge>
                    {NUDGE_OUTCOME_DESCRIPTIONS[
                      certificate.lastNudgeOutcome
                    ] ? (
                      <span className="text-xs text-muted-foreground">
                        {
                          NUDGE_OUTCOME_DESCRIPTIONS[
                            certificate.lastNudgeOutcome
                          ]
                        }
                      </span>
                    ) : null}
                  </span>
                ) : (
                  <span className="text-muted-foreground">
                    No check-in requested yet
                  </span>
                )
              }
            />
          </dl>
          {/* A check-in is a request, not a renewal. Saying so here is what
              stops "Sent to Intune" being read as "the device has a new
              certificate". */}
          <p className="border-t border-border px-4 py-2.5 text-xs text-muted-foreground">
            A check-in asks Intune to contact the device sooner than its own
            schedule would. Intune and the device decide whether it renews. If
            it does, the new certificate arrives as its own record.
          </p>
        </DetailPanel>
      </PanelMasonry>

      <DetailPanel
        title="History"
        description="Newest first."
        headerAccessory={
          historyPageData ? (
            <Badge variant="secondary">
              {historyPageData.totalElements.toLocaleString()} events
            </Badge>
          ) : null
        }
      >
        {historyQuery.error ? (
          <MachineIdentityQueryErrorState
            className="border-0"
            error={historyQuery.error}
            title="Unable to load history"
            description="This certificate's history could not be loaded."
            onRetry={() => void historyQuery.refetch()}
            isRetrying={historyQuery.isFetching}
          />
        ) : (
          <>
            <DeviceEventList
              events={historyPageData?.content}
              isLoading={historyQuery.isLoading}
              emptyMessage="No history recorded for this certificate."
            />
            {historyPageData && historyPageData.totalPages > 1 ? (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-2.5">
                <span className="text-xs text-muted-foreground">
                  Page {historyPageData.number + 1} of{" "}
                  {historyPageData.totalPages}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={historyPageData.first || historyQuery.isFetching}
                    onClick={() =>
                      setHistoryPage((current) => Math.max(0, current - 1))
                    }
                  >
                    Newer
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={historyPageData.last || historyQuery.isFetching}
                    onClick={() => setHistoryPage((current) => current + 1)}
                  >
                    Older
                  </Button>
                </div>
              </div>
            ) : null}
          </>
        )}
      </DetailPanel>
    </div>
  );
}
