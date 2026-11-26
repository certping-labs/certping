// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { CertificateManagementState } from "@/types/cert-manager";
import type { CertificateExportAvailability } from "@/types/certificate-export";

export type SSLCertificateStatus =
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

export type CertificateAuthority = "lets_encrypt" | "digicert" | "globalsign";

/** Who holds a certificate's private key. */
export type KeyCustody = "PLATFORM_HELD" | "CUSTOMER_HELD";

export interface SSLCertificateListItem {
  id?: number;
  certificateXref?: string;
  userDomainCertId?: string;
  domain: string;
  status: SSLCertificateStatus;
  rawStatus?: string;
  caProvider?: string;
  /** The issuing CA's subject, as the certificate states it (for the issuer filter). */
  issuer?: string;
  validFrom?: string | null;
  validTo?: string | null;
  san?: boolean;
  sanDomains?: string[];
  wildcard?: boolean;
  dnsConfigXref?: string;
  deploymentCredentialXrefs?: string[];
  managementState?: CertificateManagementState;
  createdAt?: string;
  updatedAt?: string;
  /** True when the backend can export this certificate's files. */
  exportAvailable?: boolean;
  keyCustody?: KeyCustody;
}

export interface SSLCertificateDetails {
  id?: number;
  certificateXref?: string;
  userDomainCertId?: string | number;
  domain: string;
  status: SSLCertificateStatus;
  rawStatus?: string;
  caProvider?: string;
  certType?: string;
  validFrom?: string;
  validTo?: string;
  certSecretHandle?: string;
  issuer?: string;
  signatureAlgorithm?: string;
  publicKeyAlgorithm?: string;
  keySize?: number;
  wildcard?: boolean;
  san?: boolean;
  sanDomains?: string[];
  dnsConfigXref?: string | Record<string, string>;
  dnsCredentialKvPath?: string | null;
  deploymentCredentialXrefs?: string[];
  deploymentCredentialKvPaths?: string[];
  managementState?: CertificateManagementState;
  serialNumber?: string;
  fingerprintSha256?: string;
  orderId?: string;
  userMessage?: string;
  lastErrorAt?: string;
  /** Per-operation trace id of the last failure; surfaced as a support "Reference ID". */
  correlationId?: string;
  /** Whether and how the certificate's files can be downloaded. */
  export?: CertificateExportAvailability;
  keyCustody?: KeyCustody;
}

export interface SanDomainConfig {
  dnsProvider?: string;
  dnsProviderToken1?: string;
  dnsProviderToken2?: string | null;
  patterns: string[];
  credentialAlias?: string;
}

export interface AccountCheckResponse {
  success: boolean;
  message: string;
  accountExists: boolean;
  code?: string;
}

export interface AccountStoreRequest {
  requestId: string;
  email: string;
  accountKey: string;
  staging: boolean;
  userId?: number;
  organizationId?: string;
  source?: string;
  requestedBy?: string;
}

export interface AccountStoreResponse {
  success: boolean;
  message: string;
  code?: string;
}

export interface ApiErrorDetails {
  detail?: string;
  code?: string;
  status?: string;
}

export interface RenewCertificateRequest {
  domain: string;
  email: string;
  credentialAlias?: string;
  dnsProvider?: string;
  dnsProviderToken1?: string;
  dnsProviderToken2?: string;
  wildcard?: boolean;
  san?: boolean;
  sanDomains?: SanDomainConfig[];
  deploymentCredentials?: string[];
  source?: string;
  requestedBy?: string;
}

export interface RenewCertificateResponse {
  success: boolean;
  error?: ApiErrorDetails | null;
  renewalStatus?: string;
  domain?: string;
  email?: string;
  validFrom?: string;
  validTo?: string;
  message?: string;
}

// Certificate Deployment Types
export type DeploymentProvider =
  "aws" | "azure" | "cloudflare" | "godaddy" | "manual";
export type DeploymentStatus =
  "pending" | "in_progress" | "completed" | "failed" | "cancelled";

export interface CertificateDeployment {
  id: string;
  certificateId: string;
  certificateDomain: string;
  provider: DeploymentProvider;
  providerIntegrationId?: string;
  status: DeploymentStatus;
  deployedAt?: string;
  createdAt: string;
  updatedAt: string;
  error?: string;
  metadata?: {
    region?: string;
    resourceId?: string;
    vaultName?: string;
    zoneId?: string;
    [key: string]: any;
  };
}

// Integration Types for Certificate Deployment Providers
export type IntegrationType =
  "aws_acm" | "azure_keyvault" | "cloudflare" | "godaddy";

export interface CertManagerIntegration {
  id: string;
  name: string;
  type: IntegrationType;
  status: "active" | "inactive" | "error";
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
  credentials: {
    // AWS ACM
    accessKeyId?: string;
    secretAccessKey?: string;
    roleArn?: string;
    region?: string;

    // Azure Key Vault
    azureClientId?: string;
    azureClientSecret?: string;
    azureOrganizationId?: string;
    azureKeyVaultUrl?: string;

    // Cloudflare
    cloudflareApiToken?: string;
    cloudflareZoneId?: string;

    // GoDaddy
    godaddyApiKey?: string;
    godaddyApiSecret?: string;
  };
  metadata?: {
    certificatesDeployed?: number;
    lastDeploymentStatus?: DeploymentStatus;
    [key: string]: any;
  };
}

// Credential Management System Types
export type CredentialProvider =
  | "aws"
  | "azure"
  | "gcp"
  | "cloudflare"
  | "godaddy"
  | "namecom"
  | "hostinger"
  | "namecheap"
  | "certping"
  | "kubernetes"
  | "akamai"
  | "f5";
export type CredentialType =
  | "aws_access_key"
  | "aws_route53"
  | "aws_acm"
  | "aws_elb"
  | "aws_cloudfront"
  | "azure_service_principal"
  | "azure_dns"
  | "azure_app_service"
  | "azure_key_vault"
  | "azure_cdn"
  | "cloudflare_api"
  | "cloudflare_api_token"
  | "cloudflare_global_key"
  | "godaddy_api"
  | "godaddy_dns"
  | "namedotcom_dns"
  | "hostinger_dns"
  | "namecheap_dns"
  | "nginx"
  | "apache"
  | "kubernetes_tls"
  | (string & {});
export type CredentialStatus = "ACTIVE" | "INACTIVE" | "PENDING_ROTATION";
export type CredentialCategory =
  "dns_credential" | "dns_provider" | "deployment_target" | (string & {});

export interface CredentialOwner {
  organizationId?: string | null;
  userId?: string | number | null;
}

export interface AwsCredInfo {
  accessKeyId: string;
  secretAccessKey: string;
  metadata: {
    region: string;
    roleArn?: string;
  };
}

export interface AzureCredInfo {
  clientId: string;
  clientSecret: string;
  organizationId: string;

  metadata: {
    keyVaultUrl: string;
  };
}

export interface CloudflareCredInfo {
  apiToken: string;
  metadata: {
    zoneId: string;
    accountId?: string;
  };
}

export interface AwsRoute53CredInfo {
  accessKeyId: string;
  secretAccessKey: string;
  metadata: {
    region: string;
  };
}

export interface GoDaddyCredInfo {
  apiKey: string;
  apiSecret: string;
  metadata?: Record<string, unknown>;
}

export interface NameDotComCredInfo {
  username: string;
  apiToken: string;
  metadata?: Record<string, unknown>;
}

export interface AwsUpdateCredInfo {
  accessKeyId: string;
  secretAccessKey: string;
  metadata?: {
    region: string;
    roleArn?: string;
  };
}

export interface AzureUpdateCredInfo {
  clientId: string;
  clientSecret: string;
  organizationId: string;
  metadata?: {
    keyVaultUrl: string;
    subscriptionId?: string;
    resourceGroup?: string;
  };
}

export interface CloudflareUpdateCredInfo {
  apiToken?: string;
  apiKey?: string;
  metadata?: {
    zoneId?: string;
    accountId?: string;
  };
}

export interface AwsRoute53UpdateCredInfo {
  accessKeyId: string;
  secretAccessKey: string;
  metadata?: {
    region: string;
  };
}

export interface GoDaddyUpdateCredInfo {
  apiKey: string;
  apiSecret: string;
  metadata?: Record<string, unknown>;
}

export interface NameDotComUpdateCredInfo {
  username: string;
  apiToken: string;
  metadata?: Record<string, unknown>;
}

export interface CredentialRotation {
  intervalDays: number;
}

export interface AddCredentialPayload {
  owner: CredentialOwner;
  alias: string;
  credentialType: CredentialType;
  provider: CredentialProvider;
  description: string;
  credentials: {
    awsCredInfo?: AwsCredInfo;
    awsRoute53CredInfo?: AwsRoute53CredInfo;
    azureCredInfo?: AzureCredInfo;
    cloudflareCredInfo?: CloudflareCredInfo;
    goDaddyCredInfo?: GoDaddyCredInfo;
    nameDotComCredInfo?: NameDotComCredInfo;
  };
  rotation: CredentialRotation;
}

export interface UpdateCredentialPayload {
  owner: CredentialOwner;
  alias: string;
  credentials: {
    awsCredInfo?: AwsUpdateCredInfo;
    awsRoute53CredInfo?: AwsRoute53UpdateCredInfo;
    azureCredInfo?: AzureUpdateCredInfo;
    cloudflareCredInfo?: CloudflareUpdateCredInfo;
    goDaddyCredInfo?: GoDaddyUpdateCredInfo;
    nameDotComCredInfo?: NameDotComUpdateCredInfo;
  };
}

export interface CredentialRecord {
  id: number;
  alias: string;
  credentialXref?: string;
  description?: string;
  credentialType: CredentialType;
  type?: string;
  provider?: CredentialProvider;
  typeName?: string;
  providerName?: string;
  providerDisplayName?: string;
  category?: CredentialCategory;
  secretHandle?: string;
  configJson?: string;
  targetType?: string;
  metadata: Record<string, string | number | null>;
  createdAt: string;
  updatedAt: string;
  nextRotationAt: string;
  rotationInterval: number;
  version: number;
  status?: CredentialStatus;
  lastError?: string;
}

export interface AddCredentialResponse {
  success: boolean;
  message: string | null;
  statusCode: number;
  id?: number;
  alias?: string;
  owner?: CredentialOwner;
  credentialType?: CredentialType;
  provider?: CredentialProvider;
  status?: CredentialStatus;
  createdAt?: string;
  updatedAt?: string;
  nextRotationAt?: string;
}

export interface GetCredentialsResponse {
  success: boolean;
  message: string | null;
  statusCode: number;
  records?: CredentialRecord[];
  content?: CredentialRecord[];
  credentials?: CredentialRecord[];
}

export interface CredentialTypeDefinition {
  typeName: CredentialType;
  description?: string;
  category: CredentialCategory;
  providerName?: string;
  providerDisplayName?: string;
}

export interface GetCredentialTypesResponse {
  success: boolean;
  message: string | null;
  statusCode: number;
  credentialTypes: CredentialTypeDefinition[];
}

export interface RotateCredentialsResponse {
  success: boolean;
  message: string;
  statusCode: number;
  rotationSummary: string;
}

// Deployment Types
export interface Owner {
  organizationId?: string | null;
  userId?: string | number | null;
}

export interface CertificateRequest {
  domain: string;
  email?: string;
}

export interface CertificateRef {
  kvSecretUri: string;
  format: "PEM";
  xref: string;
}

export interface Destination {
  provider: "aws" | "azure" | "cloudflare";
  targetType: "cloud_provider";
  credentialAlias?: string;
}

export interface ProviderCredentials {
  awsCredInfo?: {
    accessKeyId: string;
    secretAccessKey: string;
    metadata: {
      region: string;
      roleArn?: string;
    };
  };
  azureCredInfo?: {
    clientId: string;
    clientSecret: string;
    organizationId: string;
    metadata: {
      keyVaultUrl: string;
      certificateName?: string;
    };
  };
  // cloudflareCredInfo?: {
  //   apiKey: string;
  // };
}

export interface DeployCertificatePayload {
  owner: Owner;
  certificateRequest: CertificateRequest;
  certificateRef?: CertificateRef;
  destination: Destination;
  providerCredentials?: ProviderCredentials;
  requestId?: string;
  correlationId?: string;
  requestedAt: string;
  source?: string;
}

export interface DeploymentResponse {
  success: boolean;
  message: string | null;
  statusCode: number;
  deploymentId?: string;
  requestId?: string;
  correlationId?: string;
  status?: string;
}

export interface DeploymentStatusResponse {
  success?: boolean;
  statusCode?: number;
  errorMessage?: string | null;
  // If the API succeeds, the deployment status is below:
  status?: DeploymentRequestStatus | string;
  message?: string | null;
}

export type DeploymentRequestStatus =
  | "PENDING"
  | "IN_PROGRESS"
  | "SUCCESS"
  | "FAILED"
  | "FAILED_CRED_RETRIEVAL"
  | "FAILED_DEPLOY_ACCESS"
  | "FAILED_NETWORK"
  | "FAILED_CONFIGURATION"
  | "FAILED_VALIDATION"
  | (string & {});

export interface DeploymentOwner {
  organizationId: string | null;
  userId?: number | string | null;
}

export interface DeploymentCertificateRequest {
  domain: string;
  email?: string | null;
}

export interface DeploymentConfig {
  wildcard: boolean;
  san: boolean;
  sanDomains: string[];
}

export interface DeploymentCertificateRef {
  kvSecretUri?: string;
  format?: string;
  xref?: string | null;
}

export interface DeploymentDestination {
  targetType: string;
  provider: string;
  credentialAlias?: string | null;
}

export interface DeploymentRequest {
  requestId: string;
  correlationId?: string | null;
  idempotencyKey?: string | null;
  owner?: DeploymentOwner | null;
  certificateRequest: DeploymentCertificateRequest;
  certificateRef?: DeploymentCertificateRef | null;
  destination: DeploymentDestination;
  requestedAt?: number | string | null;
  status: DeploymentRequestStatus;
  message?: string | null;
  completedAt?: number | string | null;
  createdAt?: number | string | null;
  updatedAt?: number | string | null;
  requestedBy?: string | null;
  source?: string | null;
  providerCredentials?: Record<string, unknown> | null;
}

export interface DeploymentHistoryStats {
  success?: number;
  failed?: number;
  in_progress?: number;
  pending?: number;
  [key: string]: number | undefined;
}

export interface DeploymentHistoryResponse {
  success?: boolean;
  statusCode?: number;
  errorMessage?: string | null;
  deploymentRequests: DeploymentRequest[];
  totalCount?: number;
  stats?: DeploymentHistoryStats;
}

export interface DeploymentAliasEntry {
  alias: string;
  provider: string;
  target: string;
  requested_at: string;
  completed_at: string;
  status: string;
  message: string;
}

export interface DeploymentListXref {
  xref: string;
  domain: string | null;
  config?: DeploymentConfig | null;
  status?: string | null;
  validFrom?: string | null;
  validTo?: string | null;
  latestDeploymentsAtEachAliasAndNull: DeploymentAliasEntry[];
}

export interface DeploymentListResponse {
  listXrefs: DeploymentListXref[];
}

export interface DeploymentDetailResponse {
  success: boolean;
  error?: {
    detail?: string;
    code?: string;
    status?: string;
  } | null;
  xref: string;
  domain: string;
  config?: DeploymentConfig | null;
  status?: string | null;
  validFrom?: string | null;
  validTo?: string | null;
  allDeployments: DeploymentAliasEntry[];
}

export type SSLAlertSeverity = "CRITICAL" | "WARNING" | "INFO";

export interface SSLAlert {
  id: number;
  domain: string | null;
  status: string;
  createdAt: string;
  message: string | null;
  severity: SSLAlertSeverity;
  unread: boolean;
}

export interface SSLAlertsResponse {
  alerts: SSLAlert[];
}

export interface MarkAlertAsReadRequest {
  unread: boolean;
  userId?: number;
  organizationId?: string;
  requestId?: string;
}

export interface MarkAlertAsReadResponse {
  success: boolean;
  error?: {
    detail: string;
    code: string;
    status: string;
  };
}
