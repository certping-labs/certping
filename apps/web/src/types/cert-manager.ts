// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { KeyCustody } from "@/types/ssl";
import type { CredentialProvider } from "@/types/ssl";

export type CertificateManagementState =
  "manual" | "dns-managed" | "deployment-managed" | "fully-managed";

export type ManagedCertificateStatus =
  | "ACTIVE"
  | "PENDING"
  | "PENDING_DNS"
  | "AWAITING_DNS"
  | "VALIDATING"
  | "RENEWING"
  | "RENEW_SUCCESS"
  | "RENEWAL_FAILED"
  | "FAILED"
  | "EXPIRED"
  | "REVOKING"
  | "REVOKED"
  | "REVOCATION_FAILED"
  | "DELETED"
  | "CANCELLED_MANUAL"
  | (string & {});

export interface ManagedCertificateSummary {
  certificateXref: string;
  userDomainCertId?: string;
  domain: string;
  caProvider?: string;
  status: ManagedCertificateStatus;
  rawStatus: string;
  certType?: string;
  signatureAlgorithm?: string;
  publicKeyAlgorithm?: string;
  keySize?: number;
  validTo?: string | null;
  validFrom?: string | null;
  wildcard?: boolean;
  san?: boolean;
  sanDomains?: string[];
  dnsConfigXref?: string;
  dnsCredentialKvPath?: string | null;
  deploymentCredentialXrefs?: string[];
  managementState?: CertificateManagementState;
  deploymentCredentialKvPaths?: string[];
  createdAt?: string;
  updatedAt?: string;
  issuer?: string;
  serialNumber?: string;
  fingerprintSha256?: string;
  orderId?: string;
  /** True when the backend can export this certificate's files. */
  exportAvailable?: boolean;
  keyCustody?: KeyCustody;
}

export interface CertificateListPage {
  items: ManagedCertificateSummary[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
}

/**
 * Row from `GET /api/v1/certs/expiring`, without secret handles.
 * Credential and key-vault handles are not part of this projection.
 */
export interface ExpiringCertificateRow {
  domain: string;
  certificateXref: string;
  validTo: string | null;
  status: ManagedCertificateStatus;
  caProvider?: string;
}

/** Spring slice for expiring certificates. There is no total count. */
export interface ExpiringCertificatesSlice {
  items: ExpiringCertificateRow[];
  page: number;
  size: number;
  hasNext: boolean;
  withinDays: number;
}

export interface CertificateAsyncResponse {
  certificateXref: string;
  domain?: string;
  status: string;
  caProvider?: string;
  submittedAt?: string;
  revokeReason?: string;
}

export interface CertificateTxtRecord {
  recordName: string;
  recordValue: string;
  domain: string;
}

export interface SanDomainEntryInput {
  patterns: string[];
  dnsCredentialXref?: string;
}

export interface IssueCertificateInput {
  domain: string;
  wildcard: boolean;
  san: boolean;
  caProvider?: string;
  /** The CA credential (a DigiCert API key) a CA that issues on the customer's own account needs. */
  caCredentialXref?: string;
  dnsCredentialXref?: string;
  /**
   * Requested validity in days (1 to 398). Honored only by DigiCert and
   * GlobalSign; Let's Encrypt picks the lifetime itself. Omit to use the CA's default.
   */
  validityDays?: number;
  sanDomainEntries?: SanDomainEntryInput[];
  deploymentTargets?: string[];
  deploymentTargetConfigs?: DeploymentTargetConfigInput[];
}

export interface IssueManualCertificateInput {
  domain: string;
  wildcard: boolean;
  san: boolean;
  sanDomainEntries?: SanDomainEntryInput[];
}

export interface ConvertToAutomatedDnsMappingInput {
  domain: string;
  credentialXref: string;
}

export interface ConvertToAutomatedInput {
  dnsMappings: ConvertToAutomatedDnsMappingInput[];
  deploymentTargets?: string[];
  activationMode?: "IMMEDIATE" | "NEXT_RENEWAL";
  inFlightPolicy?: "WAIT" | "CANCEL_AND_REISSUE";
}

export interface ConvertToAutomatedResponse {
  certificateXref: string;
  userDomainCertId?: number;
  domain: string;
  currentStatus?: string;
  activationMode?: "IMMEDIATE" | "NEXT_RENEWAL";
  inFlightPolicy?: "WAIT" | "CANCEL_AND_REISSUE";
  plannedAction?: string;
  effectiveWhen?: string;
  convertedAt?: string;
}

export type CredentialReferenceType = "DNS" | "DEPLOYMENT";

/**
 * Read-only DISCOVERY credentials (for example an AWS Organization) come back from the list API
 * too. They only feed discovery, so they are kept out of the DNS/DEPLOYMENT form types.
 */
export const DISCOVERY_CREDENTIAL_TYPE = "DISCOVERY";

export interface CredentialReference {
  credentialXref: string;
  provider: string;
  providerKey?: CredentialProvider;
  type: CredentialReferenceType;
  description: string;
  status: string;
  /** Why a deployment target last refused this credential; cleared by an update or a later success. */
  lastError?: string;
  secretHandle?: string | null;
  configJson?: string | Record<string, unknown>;
  targetType?: string;
  createdAt?: string;
  updatedAt?: string;
  deletedAt?: string;
  message?: string;
}

export interface CredentialUpdateResponse {
  credentialXref: string;
  provider: string;
  type: CredentialReferenceType;
  status: string;
  updatedAt: string;
  message: string;
}

export interface CredentialDeleteResponse {
  credentialXref: string;
  status: "DELETED";
  deletedAt: string;
  message: string;
}

export interface CredentialReferenceList {
  items: CredentialReference[];
  totalItems: number;
}

export interface CredentialProviderOption {
  providerKey: CredentialProvider;
  apiValue: string;
  label: string;
  type: CredentialReferenceType;
  docs: string;
  logo: string;
  description: string;
  targetType?: string;
}

export interface CreateCredentialReferenceInput {
  provider: string;
  description: string;
  secretHandle?: string | null;
  credJson?: string | Record<string, unknown>;
  configJson?: string | Record<string, unknown>;
}

export type KubernetesNamespaceSecretMap =
  Array<Record<string, string>> | Record<"all_namespaces", string>;

export interface KubernetesDeploymentConfigRequestInput {
  useDefault?: boolean;
  nsSecretMap?: KubernetesNamespaceSecretMap;
}

export interface DeploymentTargetConfigInput {
  deploymentCredentialXref: string;
  config?: KubernetesDeploymentConfigRequestInput;
  targets?: Record<string, unknown>;
}

export interface DomainCredentialConfig {
  id: number;
  userDomainCertId: number;
  dnsConfig: Record<string, string>;
  deploymentTargets: string[];
  updatedAt: string;
}

export interface PatchDnsCredentialConfigInput {
  targetDomain: string;
  credentialXref: string;
}

export interface AddDeploymentTargetInput {
  credentialXref: string;
  config?: KubernetesDeploymentConfigRequestInput;
  targets?: Record<string, unknown>;
}

export interface SyncCertificateCredentialConfigInput {
  domain: string;
  currentDnsConfigXref?: string;
  dnsConfigXref?: string;
  currentDeploymentCredentialXrefs?: string[];
  deploymentCredentialXrefs?: string[];
  deploymentTargetConfigs?: Array<{
    credentialXref: string;
    config?: KubernetesDeploymentConfigRequestInput;
    targets?: Record<string, unknown>;
  }>;
}

export interface SyncCertificateCredentialConfigResult {
  didChange: boolean;
  latestConfig?: DomainCredentialConfig;
  updatedDnsConfig: boolean;
  addedDeploymentTargets: string[];
  removedDeploymentTargets: string[];
}

export interface DeploymentRecord {
  id: string | number;
  requestId?: string;
  correlationId?: string;
  organizationId?: number;
  userDomainCertId?: string | number;
  certificateXref?: string;
  domain?: string;
  deploymentCredentialXref?: string;
  targetType?: string;
  flowType?: string;
  status: string;
  wildcard?: boolean;
  san?: boolean;
  sanDomains?: string[];
  validFrom?: string;
  validTo?: string;
  issuer?: string;
  serialNumber?: string;
  fingerprintSha256?: string;
  certKvPath?: string;
  deploymentCredKvPath?: string;
  targetResourceId?: string;
  userMessage?: string;
  requestedAt?: string;
  publishedAt?: string;
  respondedAt?: string;
  createdAt?: string;
  updatedAt?: string;
  completedAt?: string;
  source?: string;
  metadata?: Record<string, unknown>;
}

export interface DeploymentQueryResult {
  items: DeploymentRecord[];
  page?: number;
  size?: number;
  totalPages?: number;
  totalItems?: number;
  mode?: string;
  summary?: DeploymentSummary;
}

export interface DeploymentSummary {
  total: number;
  success: number;
  failed: number;
  publishFailed: number;
  inProgress: number;
}

export interface DeploymentQueryFilters {
  requestId?: string;
  certificateXref?: string;
  userDomainCertificateId?: string;
  status?: string;
  targetType?: string;
  flowType?: string;
  from?: string;
  to?: string;
  view?: "list" | "summary";
  page?: number;
  size?: number;
  sort?: string;
}

export interface CreateDeploymentInput {
  certificateXref: string;
  deploymentCredentialXref: string;
  targetType: string;
  useDefault?: boolean;
  config?: KubernetesNamespaceSecretMap;
  targets?: Record<string, unknown>;
}

export interface DeploymentCredentialConfigLookup {
  certXref?: string;
  domain?: string;
  organizationId?: number;
  userDomainCertId?: number;
  deploymentCredentialXref?: string;
  deploymentCredentialId?: number;
  provider?: string;
  config?: Record<string, unknown> | null;
  targets?: Record<string, unknown> | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface UserDomainCertificateDeploymentSummary {
  userDomainCertId: number;
  domain: string;
  deploymentsRequested: number;
  deploymentsSucceeded: number;
  deploymentsFailed: number;
}

export interface UserDomainCertificateDeploymentSummaryPage {
  items: UserDomainCertificateDeploymentSummary[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
}

export interface CertificateHistoryItem {
  certificateXref: string;
  userDomainCertId: string;
  domain: string;
  caProvider?: string;
  status: ManagedCertificateStatus;
  wildcard?: boolean;
  san?: boolean;
  sanDomains?: string[];
  dnsConfigXref?: string | Record<string, string> | null;
  deploymentCredentialXrefs?: string[];
  dnsCredentialKvPath?: string | null;
  deploymentCredentialKvPaths?: string[];
  validFrom?: string | null;
  validTo?: string | null;
  certType?: string;
  signatureAlgorithm?: string;
  publicKeyAlgorithm?: string;
  keySize?: number;
  issuer: string | null;
  /** Set when a renewal produced this certificate. */
  renewalTrigger?: "SCHEDULED" | "MANUAL" | null;
}

export interface CertificateHistoryPage {
  items: CertificateHistoryItem[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
}
