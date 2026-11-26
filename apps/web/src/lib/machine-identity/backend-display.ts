// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Presentation vocabulary for the IoT device backend (device sources,
 * devices, certificate profiles). Generic helpers live in `display.ts`.
 */
import type { BadgeProps } from "@/components/ui/badge";
import { humanizeConstant } from "@/lib/machine-identity/display";
import type {
  CaConnectorStatus,
  CertificateRenewalState,
  CertificateStatus,
  DeviceSourceHealthStatus,
  DeviceSourceSyncStatus,
  DeviceStatus,
  IotProvider,
  IotRevocationReason,
  ProfileControlMode,
  ProfileLifecycleStatus,
  ProfileOrigin,
  ProfileProviderSyncStatus,
} from "@/types/machine-identity-backend";

type BadgeVariant = NonNullable<BadgeProps["variant"]>;

export const PROVIDER_LABELS: Record<IotProvider, string> = {
  INTUNE: "Microsoft Intune",
  JAMF: "Jamf Pro",
  WORKSPACE_ONE: "Omnissa Workspace ONE",
  AWS_IOT: "AWS IoT Core",
  AZURE_IOT: "Azure IoT Hub",
  GCP_IOT: "Google Cloud IoT",
  CISCO: "Cisco",
  LWM2M: "LwM2M",
  MANUAL: "Manual",
};

export interface VendorLogo {
  src: string;
  /**
   * Variant to use under a dark theme, for a mark whose colour is too dark to
   * read on a dark surface. A logo without one is legible either way and
   * renders a single image, so nothing is downloaded twice for no reason.
   */
  darkSrc?: string;
  /**
   * Intrinsic width-to-height ratio, read off the asset's own `viewBox` -
   * never guessed. The mark is laid out from this so a wide wordmark is not
   * squashed into a square slot (which made EJBCA and Smallstep render as a
   * smudge) and a square symbol is not stretched.
   */
  aspect: number;
  /**
   * The asset already spells the brand name. Rendering our own text label
   * beside it would repeat the word, so the mark carries the accessible name
   * itself instead of being decorative.
   */
  wordmark?: boolean;
}

/** Optical height every vendor mark is laid out against, in px. */
export const VENDOR_MARK_HEIGHT = 16;

/**
 * Width ceiling for one mark. A 4.6:1 wordmark at the full mark height would
 * be 74px wide and dominate a table cell, so wide marks scale down by height
 * rather than being cropped or letting the row grow.
 */
export const VENDOR_MARK_MAX_WIDTH = 56;

/** Lays a mark out at the module height unless that would exceed the width ceiling. */
export function vendorMarkSize(
  logo: VendorLogo,
  height: number = VENDOR_MARK_HEIGHT,
  maxWidth: number = VENDOR_MARK_MAX_WIDTH,
): { width: number; height: number } {
  const naturalWidth = height * logo.aspect;
  if (naturalWidth <= maxWidth) {
    return { width: Math.round(naturalWidth), height };
  }
  return { width: maxWidth, height: Math.round(maxWidth / logo.aspect) };
}

/**
 * Vendor marks, keyed by provider (sources in NOTICE). Only populated for providers we
 * actually have art for; providers without an entry fall back to text-only
 * (`ProviderLabel`) rather than a broken image.
 */
export const PROVIDER_LOGOS: Partial<Record<IotProvider, VendorLogo>> = {
  INTUNE: { src: "/assets/microsoft-intune.svg", aspect: 1 },
  JAMF: {
    src: "/assets/jamf.svg",
    darkSrc: "/assets/jamf-dark.svg",
    aspect: 1,
  },
  WORKSPACE_ONE: { src: "/assets/omnissa-workspace-one.svg", aspect: 1 },
  AWS_IOT: {
    src: "/assets/aws.svg",
    darkSrc: "/assets/aws-dark.svg",
    aspect: 1,
  },
  AZURE_IOT: { src: "/assets/azure.svg", aspect: 1 },
  GCP_IOT: { src: "/assets/gcp.svg", aspect: 1 },
};

/**
 * CA vendor marks, keyed by the free-text `caProvider` string the
 * backend reports (currently only "EJBCA" and "SMALLSTEP" are wired up to
 * anything). Unrecognized providers fall back to text-only.
 */
export const CA_PROVIDER_LOGOS: Partial<Record<string, VendorLogo>> = {
  EJBCA: {
    src: "/assets/ejbca.svg",
    darkSrc: "/assets/ejbca-dark.svg",
    aspect: 1,
  },
  SMALLSTEP: { src: "/assets/smallstep.svg", aspect: 1 },
};

/** Vendor-cased CA names; the wire value is an uppercase constant. */
export const CA_PROVIDER_LABELS: Record<string, string> = {
  EJBCA: "EJBCA",
  SMALLSTEP: "Smallstep",
};

export function caProviderLabel(caProvider: string): string {
  return CA_PROVIDER_LABELS[caProvider] ?? humanizeConstant(caProvider);
}

export function sourceHealthVariant(
  status: DeviceSourceHealthStatus,
): BadgeVariant {
  switch (status) {
    case "HEALTHY":
      return "success";
    case "DEGRADED":
    case "STALE":
      return "warning";
    case "UNHEALTHY":
      return "destructive";
    default:
      return "secondary";
  }
}

export function sourceSyncStatusVariant(
  status: DeviceSourceSyncStatus,
): BadgeVariant {
  switch (status) {
    case "OK":
      return "success";
    case "PENDING":
    case "RUNNING":
      return "info";
    case "PARTIAL":
      return "warning";
    case "FAILED":
      return "destructive";
    default:
      return "secondary";
  }
}

export const INTUNE_DEVICE_CHECK_IN_PERMISSION =
  "DeviceManagementManagedDevices.PrivilegedOperations.All";

const INTUNE_PERMISSION_LABELS: Record<string, string> = {
  "DeviceManagementManagedDevices.Read.All": "Managed device inventory",
  "Device.Read.All": "Directory device inventory",
  "DeviceManagementConfiguration.ReadWrite.All": "Certificate profiles",
  [INTUNE_DEVICE_CHECK_IN_PERMISSION]: "Device check-in",
};

export function intunePermissionLabel(permission: string): string {
  return INTUNE_PERMISSION_LABELS[permission] ?? permission;
}

export function caConnectorStatusVariant(
  status: CaConnectorStatus,
): BadgeVariant {
  switch (status) {
    case "HEALTHY":
      return "success";
    case "DEGRADED":
    case "STALE":
      return "warning";
    case "UNCONFIGURED":
      return "secondary";
    case "UNREACHABLE":
    case "UNAUTHORIZED":
    case "ERROR":
      return "destructive";
    default:
      return "secondary";
  }
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

export function providerLabel(provider: string): string {
  return PROVIDER_LABELS[provider as IotProvider] ?? humanizeConstant(provider);
}

/**
 * The SCEP enrollment path an MDM profile should point at for a source.
 *
 * <p>Path only, never a full URL: the CertPing agent that terminates SCEP runs
 * in the customer's own network and is routinely reachable only on an internal
 * hostname, so the host is the operator's to supply. The connection profile
 * ref is what routes a request to the right source, which is why it is the
 * last segment.
 */
export function scepEnrollmentPath(connectionProfileRef: string): string {
  return `/scep/v1/${encodeURIComponent(connectionProfileRef)}`;
}

export const DEVICE_STATUS_LABELS: Record<DeviceStatus, string> = {
  REGISTERED: "Registered",
  ORPHANED: "Orphaned",
  DECOMMISSIONED: "Decommissioned",
};

/**
 * ORPHANED means the device vanished from its source while CertPing may still
 * hold a live certificate for it, so it is a revocation candidate rather than
 * a neutral historical state - it reads as a warning, not as "secondary".
 */
export function deviceStatusVariant(
  status: DeviceStatus | null | undefined,
): BadgeVariant {
  switch (status) {
    case "REGISTERED":
      return "success";
    case "ORPHANED":
      return "warning";
    case "DECOMMISSIONED":
      return "secondary";
    default:
      return "outline";
  }
}

export const DEVICE_STATUS_DESCRIPTIONS: Record<DeviceStatus, string> = {
  REGISTERED: "Currently reported by its source.",
  ORPHANED:
    "No longer reported by its source. Any certificate it still holds is a revocation candidate.",
  DECOMMISSIONED:
    "Retired in CertPing. History and certificates are kept for the compliance window; the device is not retired or wiped in its source.",
};

export const COMPLIANCE_STATE_LABELS: Record<string, string> = {
  COMPLIANT: "Compliant",
  NON_COMPLIANT: "Non-compliant",
  IN_GRACE: "In grace",
  UNKNOWN: "Unknown",
};

export function complianceStateLabel(state: string | null | undefined): string {
  if (!state) return "Not reported";
  return COMPLIANCE_STATE_LABELS[state] ?? humanizeConstant(state);
}

export function complianceStateVariant(
  state: string | null | undefined,
): BadgeVariant {
  switch (state) {
    case "COMPLIANT":
      return "success";
    case "NON_COMPLIANT":
      return "destructive";
    case "IN_GRACE":
      return "warning";
    default:
      return "secondary";
  }
}

export const DEVICE_CLASS_LABELS: Record<string, string> = {
  MANAGED_ENDPOINT: "Managed endpoint",
  CONNECTED_THING: "Connected thing",
  INDUSTRIAL_ASSET: "Industrial asset",
};

export const DEVICE_OWNERSHIP_LABELS: Record<string, string> = {
  COMPANY: "Company owned",
  PERSONAL: "Personally owned",
  UNKNOWN: "Unknown",
};

export const PROFILE_LIFECYCLE_LABELS: Record<ProfileLifecycleStatus, string> =
  {
    DRAFT: "Draft",
    ACTIVE: "Active",
    ARCHIVED: "Archived",
  };

export function profileLifecycleVariant(
  status: ProfileLifecycleStatus,
): BadgeVariant {
  switch (status) {
    case "ACTIVE":
      return "success";
    case "ARCHIVED":
      return "secondary";
    default:
      return "outline";
  }
}

export const PROFILE_PLATFORM_LABELS: Record<string, string> = {
  WINDOWS: "Windows",
  MACOS: "macOS",
  IOS: "iOS",
  IPADOS: "iPadOS",
  ANDROID: "Android",
  LINUX: "Linux",
};

export const PROFILE_KIND_LABELS: Record<string, string> = {
  CERTIFICATE_ENROLLMENT: "Certificate enrollment",
  TRUST_ANCHOR: "Trust anchor",
  PROVISIONING_TEMPLATE: "Provisioning template",
  ENROLLMENT_GROUP: "Enrollment group",
};

export const PROFILE_ENROLLMENT_METHOD_LABELS: Record<string, string> = {
  SCEP: "SCEP",
  PKCS: "PKCS",
  NONE: "None",
};

export const KEY_STORAGE_PROVIDER_LABELS: Record<string, string> = {
  useTpmKspOtherwiseUseSoftwareKsp: "TPM, otherwise software",
  useTpmKspOtherwiseFail: "TPM only",
  usePassportForWorkKspOtherwiseFail: "Windows Hello for Business",
  useSoftwareKsp: "Software",
};

export const PROFILE_SAN_TYPE_LABELS: Record<string, string> = {
  EMAIL: "Email",
  UPN: "UPN",
  DNS: "DNS",
  URI: "URI",
};

export const PROFILE_CONTROL_MODE_LABELS: Record<ProfileControlMode, string> = {
  CMS_MANAGED: "CertPing managed",
  OBSERVED_ONLY: "Observed only",
};

export const PROFILE_ORIGIN_LABELS: Record<ProfileOrigin, string> = {
  CMS_CREATED: "Created in CertPing",
  PROVIDER_DISCOVERED: "Discovered from provider",
};

export const PROFILE_PROVIDER_SYNC_STATUS_LABELS: Record<
  ProfileProviderSyncStatus,
  string
> = {
  NEVER: "Never synced",
  PENDING: "Pending",
  IN_SYNC: "In sync",
  FAILED: "Failed",
  DRIFTED: "Drifted",
  NOT_FOUND: "Missing",
};

export function profileProviderSyncStatusVariant(
  status: ProfileProviderSyncStatus,
): BadgeVariant {
  switch (status) {
    case "IN_SYNC":
      return "success";
    case "PENDING":
      return "info";
    case "DRIFTED":
      return "warning";
    case "FAILED":
    case "NOT_FOUND":
      return "destructive";
    default:
      return "secondary";
  }
}

export const CERTIFICATE_STATUS_LABELS: Record<CertificateStatus, string> = {
  ISSUED: "Issued",
  EXPIRING: "Expiring",
  EXPIRED: "Expired",
  REVOCATION_PENDING: "Revoking",
  REVOCATION_DISPATCHED: "Revoking",
  REVOKED: "Revoked",
  REVOCATION_FAILED: "Revoke failed",
  REVOCATION_OUTCOME_UNKNOWN: "Unconfirmed",
};

/**
 * Looks a display status up without ever rendering `undefined`.
 *
 * <p>`status` is a backend string, not a closed enum on the wire: the server
 * passes any non-issued lifecycle value straight through, so a state added
 * there before it is added here must still read as something.
 */
export function certificateStatusLabel(status: string): string {
  return (
    CERTIFICATE_STATUS_LABELS[status as CertificateStatus] ??
    humanizeConstant(status)
  );
}

/**
 * `REVOCATION_OUTCOME_UNKNOWN` is deliberately destructive rather than a
 * warning: the CA never confirmed, so the certificate may still be live and
 * trusted while the record says it was revoked. That is the more dangerous of
 * the two readings, and the badge should say so.
 */
export function certificateStatusVariant(
  status: CertificateStatus,
): BadgeVariant {
  switch (status) {
    case "ISSUED":
      return "success";
    case "EXPIRING":
      return "warning";
    case "EXPIRED":
    case "REVOCATION_FAILED":
    case "REVOCATION_OUTCOME_UNKNOWN":
      return "destructive";
    case "REVOCATION_PENDING":
    case "REVOCATION_DISPATCHED":
      return "info";
    case "REVOKED":
      return "secondary";
    default:
      return "secondary";
  }
}

/** True while a revocation this app requested is still in flight at the CA. */
export function isRevocationInFlight(status: CertificateStatus): boolean {
  return status === "REVOCATION_PENDING" || status === "REVOCATION_DISPATCHED";
}

/**
 * Whether the revoke action can do anything. Mirrors the backend's own guard
 * so the button is disabled rather than offered and then refused: CA
 * certificates and CAs without a revocation path are `422`, an in-flight or
 * completed revocation is `409`.
 */
export function canRequestRevocation(certificate: {
  status: CertificateStatus;
  caProvider: string;
  certificateAuthority?: boolean;
}): boolean {
  if (certificate.certificateAuthority) return false;
  if (!REVOCABLE_CA_PROVIDERS.has(certificate.caProvider.toUpperCase())) {
    return false;
  }
  return (
    !isRevocationInFlight(certificate.status) &&
    certificate.status !== "REVOKED"
  );
}

/** The CA providers with a wired revocation path; anything else is a `422`. */
const REVOCABLE_CA_PROVIDERS = new Set(["EJBCA", "SMALLSTEP"]);

export const REVOCATION_REASON_LABELS: Record<IotRevocationReason, string> = {
  UNSPECIFIED: "Unspecified",
  KEY_COMPROMISE: "Key compromise",
  AFFILIATION_CHANGED: "Affiliation changed",
  SUPERSEDED: "Superseded",
  CESSATION_OF_OPERATION: "Cessation of operation",
  PRIVILEGES_WITHDRAWN: "Privileges withdrawn",
};

/** What each reason actually means, so the choice is not a guess from its name. */
export const REVOCATION_REASON_DESCRIPTIONS: Record<
  IotRevocationReason,
  string
> = {
  UNSPECIFIED: "No reason is recorded on the CRL entry.",
  KEY_COMPROMISE:
    "The private key is known or suspected to be in the wrong hands. Irreversible, and relying parties treat it as the most serious reason.",
  AFFILIATION_CHANGED:
    "The subject's name or affiliation changed, so the certificate no longer describes it correctly.",
  SUPERSEDED: "A replacement certificate has been issued for the same subject.",
  CESSATION_OF_OPERATION:
    "The device or service the certificate was issued for is being retired.",
  PRIVILEGES_WITHDRAWN:
    "The subject is no longer authorized for what the certificate grants.",
};

export const CERTIFICATE_RENEWAL_STATE_LABELS: Record<
  CertificateRenewalState,
  string
> = {
  NONE: "No request",
  NUDGING: "Check-in requested",
  RENEWED: "Renewed",
};

export function certificateRenewalStateVariant(
  state: CertificateRenewalState,
): BadgeVariant {
  switch (state) {
    case "NUDGING":
      return "info";
    case "RENEWED":
      return "success";
    default:
      return "secondary";
  }
}

/**
 * Whether a renewal state is worth surfacing as its own badge. `NONE` is the
 * default resting state (no check-in has been requested), so it reads as noise
 * next to the always-present {@link CertificateStatus} badge.
 */
export function isRenewalStateSurfaced(
  state: CertificateRenewalState,
): boolean {
  return state !== "NONE";
}

/**
 * The agent's reported check-in outcome. `NUDGE_SENT` means Intune accepted
 * the request, never that the device answered it - the wording keeps that
 * distinction, because an operator reading "renewed" here would stop watching.
 */
export const NUDGE_OUTCOME_LABELS: Record<string, string> = {
  REQUESTED: "Requested",
  NUDGE_SENT: "Sent to Intune",
  INTUNE_REJECTED: "Rejected",
  INTUNE_UNAVAILABLE: "Intune unreachable",
  SKIPPED_UNSUPPORTED: "Unsupported",
  PUBLISH_FAILED: "Dispatch failed",
};

/**
 * The sentence behind each pill, for a detail panel that has room for it.
 * Split from the labels because "Sent to Intune" has to fit a table cell while
 * still not being read as "the device renewed".
 */
export const NUDGE_OUTCOME_DESCRIPTIONS: Record<string, string> = {
  REQUESTED: "Queued in CertPing, waiting for the agent to pick it up.",
  NUDGE_SENT:
    "Intune accepted the check-in request. Intune and the device decide whether it actually renews.",
  INTUNE_REJECTED: "Intune refused the check-in request.",
  INTUNE_UNAVAILABLE: "The agent could not reach Intune.",
  SKIPPED_UNSUPPORTED: "This device does not support an on-demand check-in.",
  PUBLISH_FAILED:
    "CertPing could not publish the command to the agent, so nothing was requested.",
};

export function nudgeOutcomeLabel(outcome: string): string {
  return NUDGE_OUTCOME_LABELS[outcome] ?? humanizeConstant(outcome);
}

export function nudgeOutcomeVariant(outcome: string): BadgeVariant {
  switch (outcome) {
    case "NUDGE_SENT":
      return "success";
    case "REQUESTED":
      return "info";
    case "SKIPPED_UNSUPPORTED":
      return "secondary";
    default:
      return "destructive";
  }
}
/**
 * RFC 5280 §4.2.1.6 GeneralName choices, as the backend serializes the raw
 * ASN.1 tag name (e.g. "dNSName") rather than a CertPing enum.
 */
export const SAN_TYPE_LABELS: Record<string, string> = {
  otherName: "Other",
  rfc822Name: "Email",
  dNSName: "DNS",
  x400Address: "X.400 address",
  directoryName: "Directory name",
  ediPartyName: "EDI party name",
  uniformResourceIdentifier: "URI",
  iPAddress: "IP address",
  registeredID: "Registered ID",
};

export function sanTypeLabel(type: string): string {
  return SAN_TYPE_LABELS[type] ?? type;
}

/** Standard RFC 5280 extended key usage OIDs. Unrecognized OIDs render as-is. */
export const EXTENDED_KEY_USAGE_LABELS: Record<string, string> = {
  "2.5.29.37.0": "Any extended key usage",
  "1.3.6.1.5.5.7.3.1": "Server authentication",
  "1.3.6.1.5.5.7.3.2": "Client authentication",
  "1.3.6.1.5.5.7.3.3": "Code signing",
  "1.3.6.1.5.5.7.3.4": "Email protection",
  "1.3.6.1.5.5.7.3.5": "IPsec end system",
  "1.3.6.1.5.5.7.3.6": "IPsec tunnel",
  "1.3.6.1.5.5.7.3.7": "IPsec user",
  "1.3.6.1.5.5.7.3.8": "Time stamping",
  "1.3.6.1.5.5.7.3.9": "OCSP signing",
};

export function extendedKeyUsageLabel(oid: string): string {
  return EXTENDED_KEY_USAGE_LABELS[oid] ?? oid;
}

/** Describes a key as `RSA 2048` or, for curve-based algorithms, `EC secp256r1`. */
export function formatKeyStrength(certificate: {
  keyAlgorithm: string;
  keySize: number | null;
  publicKeyCurve?: string | null;
}): string {
  if (certificate.keySize)
    return `${certificate.keyAlgorithm} ${certificate.keySize}`;
  return certificate.publicKeyCurve
    ? `${certificate.keyAlgorithm} ${certificate.publicKeyCurve}`
    : certificate.keyAlgorithm;
}

/** Human phrasing for a certificate's remaining lifetime, including the expired case. */
export function formatRemainingLifetime(remainingDays: number): string {
  if (remainingDays < 0) {
    const overdue = Math.abs(remainingDays);
    return `Expired ${overdue} ${overdue === 1 ? "day" : "days"} ago`;
  }
  if (remainingDays === 0) return "Expires today";
  if (remainingDays === 1) return "1 day left";
  return `${remainingDays} days left`;
}
