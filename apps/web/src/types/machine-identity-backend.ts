// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Types for the real IoT device identity backend (the server's `/api/v1/iot/*`
 * and `/api/v1/machine-identity/profiles*`).
 *
 * <p>Field names below match the backend's JSON verbatim (camelCase record
 * component names, no renames); only a few generic nouns (Health, Sync,
 * Owner) are prefixed for readability since the backend does not mandate a
 * TypeScript interface name.
 */
import type { PageRequestParams, SpringPage } from "@/types/pagination";

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

/** Every provider the backend schema recognizes; only INTUNE has a live agent connector today. */
export type IotProvider =
  | "INTUNE"
  | "JAMF"
  | "WORKSPACE_ONE"
  | "AWS_IOT"
  | "AZURE_IOT"
  | "GCP_IOT"
  | "CISCO"
  | "LWM2M"
  | "MANUAL";

// ---------------------------------------------------------------------------
// Device sources
// ---------------------------------------------------------------------------

export type DeviceSourceHealthStatus =
  "HEALTHY" | "DEGRADED" | "UNHEALTHY" | "UNKNOWN" | "STALE";
export type DeviceSourceReportedStatus =
  "HEALTHY" | "DEGRADED" | "UNHEALTHY" | "UNKNOWN";
export type DeviceSourceSyncStatus =
  "PENDING" | "RUNNING" | "OK" | "PARTIAL" | "FAILED";
export type DeviceSourceStatus = "ACTIVE" | "DISABLED";

/**
 * One provider API permission the agent probed on its last health check, e.g.
 * a Microsoft Graph application role. The backend lifts these out of the
 * health `metadata` blob, so they are never present there and must be read
 * from `permissions`.
 */
export interface DeviceSourcePermission {
  name: string;
  granted: boolean;
}

export interface DeviceSourceHealth {
  status: DeviceSourceHealthStatus;
  reportedStatus: DeviceSourceReportedStatus;
  stale: boolean;
  providerStatus: string;
  statusMessage: string | null;
  /** Empty when the agent's health report carried no permission probe. */
  permissions: DeviceSourcePermission[];
  metadata: Record<string, unknown>;
  observedAt: string;
  receivedAt: string;
  staleAt: string;
  responseTimeMs: number | null;
}

export interface DeviceSourceSync {
  syncXref: string;
  status: DeviceSourceSyncStatus;
  requestedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  expectedDeviceCount: number | null;
  processedDeviceCount: number | null;
  failedDeviceCount: number | null;
  processedBatchCount: number | null;
  expectedBatchCount: number | null;
  completionReceived: boolean;
  lastError: string | null;
}

export interface DeviceSourceDto {
  sourceXref: string;
  provider: string;
  sourceCategory: string;
  connectionProfileRef: string;
  displayName: string;
  description: string | null;
  configurationMetadata: Record<string, unknown> | null;
  syncEnabled: boolean;
  status: DeviceSourceStatus;
  firstAdvertisedAt: string;
  lastAdvertisedAt: string;
  health: DeviceSourceHealth | null;
  sync: DeviceSourceSync | null;
  deviceCount: number;
}

export interface DeviceSourceEventDto {
  eventXref: string;
  eventType: string;
  eventStatus: string;
  correlationId: string | null;
  detail: Record<string, unknown> | null;
  occurredAt: string;
  receivedAt: string;
}

// ---------------------------------------------------------------------------
// CA connectors
// ---------------------------------------------------------------------------

export type CaConnectorStatus =
  | "HEALTHY"
  | "DEGRADED"
  | "UNCONFIGURED"
  | "UNREACHABLE"
  | "UNAUTHORIZED"
  | "ERROR"
  | "UNKNOWN"
  | "STALE";

/**
 * A configured CA connector (EJBCA or Smallstep today) and its latest
 * reported health, one entry per `(organizationId, connectorId)`, updated by
 * the agent's `AGENT_CA_HEALTH_REPORT` message. `product`, `profiles`, and
 * `issues` are arbitrary provider JSON (shape depends on the CA) - not
 * fixed by this DTO. Same shape for both the list and single-connector
 * responses.
 */
export interface CaConnectorResponse {
  connectorId: string;
  caProvider: string;
  enabled: boolean;
  /** The reported status, or STALE once the last report is older than the health freshness window. */
  status: CaConnectorStatus;
  reportedStatus: CaConnectorStatus;
  stale: boolean;
  staleAt: string;
  checkedAt: string;
  respondedAt: string | null;
  receivedAt: string;
  latencyMs: number | null;
  endpoint: string | null;
  authMethod: string | null;
  product: unknown;
  capabilities: string[];
  profiles: unknown;
  issues: unknown;
  reportVersion: number;
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

export type DeviceStatus = "REGISTERED" | "ORPHANED" | "DECOMMISSIONED";

/**
 * Device list row. Note there is no `provider`/`sourceXref` field here even
 * though `GET /devices` accepts a `source` filter, so a "Source" column
 * cannot be rendered from this shape — use `platformDisplayName` instead.
 */
export interface DeviceListItem {
  deviceXref: string;
  deviceName: string | null;
  serialNumber: string | null;
  deviceClass: string | null;
  operatingSystem: string | null;
  osVersion: string | null;
  model: string | null;
  ownerUpn: string | null;
  ownerDisplayName: string | null;
  complianceState: string | null;
  status: DeviceStatus | null;
  platformDisplayName: string | null;
  lastSeenInSourceAt: string | null;
}

/** Subset of `DeviceSourceDto` embedded in `DeviceDetail` (no health/sync/deviceCount). */
export interface DeviceSourceRef {
  sourceXref: string;
  provider: string;
  sourceCategory: string;
  connectionProfileRef: string;
  displayName: string;
  description: string | null;
  configurationMetadata: Record<string, unknown> | null;
  syncEnabled: boolean;
  status: DeviceSourceStatus;
}

export interface DeviceEndpointPosture {
  operatingSystem: string | null;
  osVersion: string | null;
  complianceState: string | null;
  complianceStateRaw: string | null;
  jailbrokenState: string | null;
  managementAgent: string | null;
  enrollmentType: string | null;
  encrypted: boolean | null;
  supervised: boolean | null;
  mdmEnrolledAt: string | null;
  mdmLastSyncAt: string | null;
  vendorAttributes: Record<string, unknown> | null;
}

export interface DeviceConnectedThing {
  attestationType: string | null;
  hubOrAccountRef: string | null;
  thingType: string | null;
  formFactor: string | null;
  connectivityState: string | null;
  lastConnectedAt: string | null;
  customAttributes: Record<string, unknown> | null;
}

export interface DeviceOwner {
  upn: string | null;
  email: string | null;
  displayName: string | null;
  updatedAt: string | null;
}

export interface DeviceProviderData {
  schemaVersion: number;
  updatedAt: string;
  attributes: Record<string, unknown>;
}

export interface DeviceDetail {
  deviceXref: string;
  source: DeviceSourceRef;
  sourceDeviceId: string;
  sourceIdentifiers: Record<string, unknown> | null;
  deviceClass: string | null;
  serialNumber: string | null;
  deviceName: string | null;
  manufacturer: string | null;
  model: string | null;
  ownership: string | null;
  status: DeviceStatus | null;
  /** Hidden from the inventory by an operator. The row and its history are intact. */
  archived: boolean;
  registeredAt: string | null;
  lastSeenInSourceAt: string | null;
  decommissionedAt: string | null;
  endpointPosture: DeviceEndpointPosture | null;
  connectedThing: DeviceConnectedThing | null;
  owner: DeviceOwner | null;
  providerData: DeviceProviderData | null;
  createdAt: string;
  updatedAt: string;
}

export interface DeviceEventDto {
  eventXref: string;
  eventType: string | null;
  eventStatus: string | null;
  eventMessage: string | null;
  actorSource: string | null;
  actorUserId: number | null;
  correlationId: string | null;
  detail: Record<string, unknown> | null;
  occurredAt: string;
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/**
 * Display status the backend computes per row.
 *
 * <p>Only the three lifetime buckets are derived; every other stored lifecycle
 * value passes straight through, so a revoked or revoking certificate reports
 * its raw state here. All eight must be handled - a label map missing the
 * revocation states renders `undefined` in the badge.
 */
export type CertificateStatus =
  | "ISSUED"
  | "EXPIRING"
  | "EXPIRED"
  | "REVOCATION_PENDING"
  | "REVOCATION_DISPATCHED"
  | "REVOKED"
  | "REVOCATION_FAILED"
  | "REVOCATION_OUTCOME_UNKNOWN";

/**
 * The subset `GET /iot/certificates?status=` accepts. Deliberately narrower
 * than {@link CertificateStatus}: the server's filter enum is only the three
 * lifetime buckets, and sending `REVOKED` would be a 400.
 */
export type CertificateStatusFilter = "ISSUED" | "EXPIRING" | "EXPIRED";

/**
 * Persisted renewal-monitoring lifecycle state, distinct from the computed
 * {@link CertificateStatus}: `EXPIRING` is derived at read time from
 * `validTo`, whereas `renewalState` is a stored value driven by an
 * operator-requested Intune check-in and a subsequently observed renewal.
 * Constrained to these three values by the certificate table's own check.
 */
export type CertificateRenewalState = "NONE" | "NUDGING" | "RENEWED";

export interface CertificateDeviceSummary {
  deviceXref: string;
  deviceName: string | null;
  /** Null in list rows - the backend only populates this for the detail call. */
  status: string | null;
  /**
   * The device was taken out of the inventory by an operator. The certificate is still attributed
   * to it, which is why the summary is present at all rather than null.
   */
  archived: boolean;
}

export interface CertificateProfileSummary {
  profileXref: string;
  name: string;
}

export interface CertificateListItem {
  certificateXref: string;
  commonName: string;
  serialNumber: string;
  status: CertificateStatus;
  validFrom: string;
  validTo: string;
  issuedAt: string;
  remainingDays: number;
  caProvider: string;
  /** Not every CA/profile combination sets this. */
  caName: string | null;
  issuerDn: string;
  /** Not every CA/profile combination sets this. */
  certificateScope: "DEVICE" | "USER" | null;
  device: CertificateDeviceSummary | null;
  profile: CertificateProfileSummary | null;
  keyAlgorithm: string;
  keySize: number | null;
  signatureAlgorithm: string;
  signatureAlgorithmOid: string;
  /** Renewal-monitoring lifecycle state (see {@link CertificateRenewalState}). */
  renewalState: CertificateRenewalState;
  /** How many times an Intune check-in has been requested for this certificate. */
  nudgeAttempts: number;
  lastNudgedAt: string | null;
  /**
   * The agent's last reported check-in outcome (`NUDGE_SENT`,
   * `INTUNE_REJECTED`, `INTUNE_UNAVAILABLE`, `SKIPPED_UNSUPPORTED`,
   * `PUBLISH_FAILED`), or `REQUESTED` while the command is still in flight.
   */
  lastNudgeOutcome: string | null;
}

export interface CertificateSubjectAlternativeName {
  /** Raw ASN.1 GeneralName tag, e.g. "dNSName", not a CertPing enum. */
  type: string;
  oid: string | null;
  value: string;
}

export interface CertificateEnrollmentSummary {
  enrollmentXref: string;
  enrollmentType: string;
  transactionId: string;
  status: string;
  /**
   * Whether the enrollment was correlated to a known device. Certificates are
   * persisted source-first, so an unmatched enrollment is a real, expected
   * state rather than an error.
   */
  deviceMatchStatus: string | null;
  /** Same, for the certificate profile the enrollment resolved to. */
  profileResolutionStatus: string | null;
  priorCertificateSerialNumber: string | null;
  requestedAt: string;
  validatedAt: string | null;
  issuedAt: string | null;
  completedAt: string | null;
}

export interface CertificateDetail extends CertificateListItem {
  subjectDn: string;
  subjectAlternativeNames: CertificateSubjectAlternativeName[];
  keyUsages: string[];
  extendedKeyUsageOids: string[];
  certificatePolicyOids: string[];
  publicKeyCurve: string | null;
  subjectKeyIdentifier: string | null;
  authorityKeyIdentifier: string | null;
  fingerprintSha256: string;
  certificateAuthority: boolean;
  caEndEntityName: string | null;
  caProvisionerName: string | null;
  enrollment: CertificateEnrollmentSummary | null;
}

// ---------------------------------------------------------------------------
// Certificate revocation
// ---------------------------------------------------------------------------

/**
 * The RFC 5280 leaf reasons both EJBCA and Smallstep accept. Deliberately
 * short of the full RFC set: the backend enum only carries reasons that are
 * safe and supported on every wired CA.
 */
export type IotRevocationReason =
  | "UNSPECIFIED"
  | "KEY_COMPROMISE"
  | "AFFILIATION_CHANGED"
  | "SUPERSEDED"
  | "CESSATION_OF_OPERATION"
  | "PRIVILEGES_WITHDRAWN";

/**
 * Lifecycle of one revocation operation. `OUTCOME_UNKNOWN` is terminal but
 * inconclusive - the CA was reached and never confirmed, so the certificate
 * must be treated as possibly still live.
 */
export type IotRevocationStatus =
  "PENDING" | "DISPATCHED" | "CONFIRMED" | "FAILED" | "OUTCOME_UNKNOWN";

/** Who asked for the revocation: an operator here, or Intune's own request queue. */
export type IotRevocationSource = "UI" | "INTUNE";

export interface CreateIotRevocationRequest {
  reason: IotRevocationReason;
  /** Free text kept on the operation record; the backend caps it at 500 characters. */
  operatorNote?: string;
}

/**
 * `202 Accepted` body. The CA has not been contacted yet - the agent picks the
 * operation up asynchronously, so `status` is `PENDING` on the first response
 * and the certificate itself is the thing to watch for the outcome.
 */
export interface IotRevocationResponse {
  operationXref: string;
  certificateXref: string;
  status: IotRevocationStatus;
  reason: IotRevocationReason;
  source: IotRevocationSource;
  attemptCount: number;
  requestedAt: string;
  completedAt: string | null;
  errorCode: string | null;
  errorMessage: string | null;
}

export interface CertificateListParams extends PageRequestParams {
  deviceXref?: string;
  profileXref?: string;
  sourceXref?: string;
  caProvider?: string;
  status?: CertificateStatusFilter;
  renewalState?: CertificateRenewalState;
  expiringWithinDays?: number;
  /** Maps to the wire query param `q`. */
  search?: string;
}

export type CertificateListPage = SpringPage<CertificateListItem>;

export type DeviceSyncResultStatus = "QUEUED" | "SKIPPED";

export type DeviceSyncSkipReason =
  | "DEVICE_NOT_FOUND"
  | "UNSUPPORTED_OR_INACTIVE_SOURCE"
  | "NO_MANAGED_DEVICE_ID"
  | "NO_CURRENT_CERTIFICATE"
  | "OUTSIDE_RENEWAL_THRESHOLD"
  | "PROFILE_THRESHOLD_UNAVAILABLE"
  | "COOLDOWN_ACTIVE";

export interface DeviceSyncRequest {
  deviceXrefs: string[];
}

export type DeviceSyncSelection =
  { all: true; deviceXrefs?: never } | { all?: false; deviceXrefs: string[] };

export interface DeviceSyncDeviceResult {
  deviceXref: string;
  status: DeviceSyncResultStatus;
  reason: DeviceSyncSkipReason | null;
  certificateXrefs: string[];
  nextAllowedAt: string | null;
}

/**
 * Per-device acceptance report from the asynchronous Intune check-in endpoint.
 * `QUEUED` means the command was published, never that the device checked in
 * or renewed.
 */
export interface DeviceSyncResponse {
  selectedDevices: number;
  queuedDevices: number;
  skippedDevices: number;
  devices: DeviceSyncDeviceResult[];
}

// ---------------------------------------------------------------------------
// Fleet summary
// ---------------------------------------------------------------------------

export interface IotSourceDeviceCount {
  sourceXref: string;
  displayName: string;
  provider: string;
  deviceCount: number;
}

export interface IotBooleanBreakdown {
  yes: number;
  no: number;
  unknown: number;
}

export interface IotSourceOverview {
  total: number;
  syncEnabled: number;
  healthy: number;
  degraded: number;
  unhealthy: number;
  stale: number;
  unknown: number;
}

export interface IotSummary {
  totalDevices: number;
  activeDevices: number;
  byStatus: Record<string, number>;
  byProvider: Record<string, number>;
  byDeviceClass: Record<string, number>;
  byOwnership: Record<string, number>;
  byOperatingSystem: Record<string, number>;
  byComplianceState: Record<string, number>;
  bySource: IotSourceDeviceCount[];
  encryption: IotBooleanBreakdown;
  supervision: IotBooleanBreakdown;
  sources: IotSourceOverview;
  lastSyncCompletedAt: string | null;
}

// ---------------------------------------------------------------------------
// Certificate profiles
// ---------------------------------------------------------------------------

export type ProfileLifecycleStatus = "DRAFT" | "ACTIVE" | "ARCHIVED";
export type ProfileOrigin = "CMS_CREATED" | "PROVIDER_DISCOVERED";
export type ProfileControlMode = "CMS_MANAGED" | "OBSERVED_ONLY";
export type ProfileKind =
  | "CERTIFICATE_ENROLLMENT"
  | "TRUST_ANCHOR"
  | "PROVISIONING_TEMPLATE"
  | "ENROLLMENT_GROUP";
export type ProfileEnrollmentMethod = "SCEP" | "PKCS" | "NONE";
/**
 * `NOT_FOUND` is set only by a completed provider inventory that proved the
 * profile is gone, and it is the one state `DELETE /profiles/{xref}` accepts -
 * the backend 409s an archive attempt from any other state.
 */
export type ProfileProviderSyncStatus =
  "NEVER" | "PENDING" | "IN_SYNC" | "FAILED" | "DRIFTED" | "NOT_FOUND";
export type ProfileCertificateScope = "DEVICE" | "USER";
/** NOTE: "EC", not "ECDSA". */
export type ProfileKeyAlgorithm = "RSA" | "EC";
export type ProfileValidityUnit = "DAYS" | "MONTHS" | "YEARS";
export type ProfileSanType = "EMAIL" | "UPN" | "DNS" | "URI";

export interface ProfileSanFormat {
  type: ProfileSanType;
  format: string;
}

export interface ProfileExtendedKeyUsage {
  objectIdentifier: string;
  name?: string;
}

export interface ProfileConfiguration {
  issuerXref: string | null;
  certificateScope: ProfileCertificateScope | null;
  keyAlgorithm: ProfileKeyAlgorithm | null;
  keySize: number | null;
  curve: string | null;
  signatureHash: string | null;
  subjectNameFormat: string | null;
  subjectAltNameFormats: ProfileSanFormat[];
  extendedKeyUsages: ProfileExtendedKeyUsage[];
  keyUsages: string[];
  validityValue: number | null;
  validityUnit: ProfileValidityUnit | null;
  renewalWindowDays: number | null;
  keyExportable: boolean | null;
  providerConfig: Record<string, unknown>;
}

export interface ProfileProviderSnapshot {
  response: Record<string, unknown>;
  schemaVersion: number;
  providerVersion: string | null;
  providerLastModifiedAt: string | null;
  providerObservedAt: string;
}

export interface CertificateProfileResponse {
  profileXref: string;
  sourceXref: string;
  sourceDisplayName: string;
  provider: string;
  name: string;
  description: string | null;
  targetPlatform: string;
  targetVariant: string;
  providerProfileType: string | null;
  providerProfileId: string | null;
  lifecycleStatus: ProfileLifecycleStatus;
  profileOrigin: ProfileOrigin;
  controlMode: ProfileControlMode;
  profileKind: ProfileKind;
  enrollmentMethod: ProfileEnrollmentMethod | null;
  desiredRevision: number;
  appliedRevision: number | null;
  latestOperationXref: string | null;
  latestOperationStartedAt: string | null;
  latestOperationCompletedAt: string | null;
  providerSyncStatus: ProfileProviderSyncStatus;
  providerSyncError: string | null;
  lastProviderSyncedAt: string | null;
  configuration: ProfileConfiguration | null;
  /** Always null in list responses; populated only when fetching a single profile. */
  providerSnapshot: ProfileProviderSnapshot | null;
  createdAt: string;
  updatedAt: string;
  rowVersion: number;
}

export interface ProfileConfigurationInput {
  issuerXref?: string;
  certificateScope?: ProfileCertificateScope;
  keyAlgorithm?: ProfileKeyAlgorithm;
  keySize?: number;
  curve?: string;
  signatureHash?: string;
  subjectNameFormat?: string;
  subjectAltNameFormats?: { type: string; format: string }[];
  extendedKeyUsages?: { objectIdentifier: string; name?: string }[];
  keyUsages?: string[];
  validityValue?: number;
  validityUnit?: ProfileValidityUnit;
  renewalWindowDays?: number;
  keyExportable?: boolean | null;
  providerConfig?: Record<string, unknown>;
}

export interface CreateCertificateProfileRequest {
  name: string;
  description?: string;
  sourceXref: string;
  lifecycleStatus: ProfileLifecycleStatus;
  targetPlatform: string;
  targetVariant?: string;
  profileKind: ProfileKind;
  enrollmentMethod?: ProfileEnrollmentMethod;
  configuration: ProfileConfigurationInput;
}

export interface UpdateCertificateProfileRequest {
  name: string;
  description?: string;
  lifecycleStatus: ProfileLifecycleStatus;
  /** Captured from the currently-loaded profile's `rowVersion`, not a form field. */
  expectedVersion: number;
  confirmReissuance: boolean;
  configuration: ProfileConfigurationInput;
}

// ---------------------------------------------------------------------------
// List params, pages, and async-action responses
// ---------------------------------------------------------------------------

export interface DeviceSourceEventListParams extends PageRequestParams {
  correlationId?: string;
}

export interface DeviceListParams extends PageRequestParams {
  source?: string;
  status?: DeviceStatus;
  complianceState?: string;
  os?: string;
  /** Maps to the wire query param `q`. */
  search?: string;
}

export type DeviceEventListParams = PageRequestParams;

export interface ProfileListParams extends PageRequestParams {
  sourceXref?: string;
  lifecycleStatus?: ProfileLifecycleStatus;
  controlMode?: ProfileControlMode;
  providerSyncStatus?: ProfileProviderSyncStatus;
  targetPlatform?: string;
  search?: string;
}

export interface SourceSyncAcceptedResponse {
  status: "ACCEPTED";
  sourceXref: string;
  syncXref: string;
}

export interface ProfileDiscoverySyncAcceptedResponse {
  status: string;
  sourceXref: string;
  requestXref: string;
}

export type DeviceSourcePage = DeviceSourceDto[];
export type DeviceSourceEventPage = SpringPage<DeviceSourceEventDto>;
export type DevicePage = SpringPage<DeviceListItem>;
export type DeviceEventPage = SpringPage<DeviceEventDto>;
export type CertificateProfilePage = SpringPage<CertificateProfileResponse>;
export type ProfileEventPage = SpringPage<DeviceSourceEventDto>;

export interface MachineIdentityBackendError {
  status: number;
  error: string;
  message: string;
  path: string;
  timestamp: string;
  code?: string;
  feature?: string;
}
