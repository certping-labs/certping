// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export const DISCOVERED_CERTS_PAGE_SIZE = 100;

export interface DiscoveredCert {
  id: number;
  organizationId: number;
  targetType: string;
  resourceId: string;
  domain: string | null;
  keyAlgorithm: string | null;
  signatureAlgorithm: string | null;
  notBefore: string | null;
  notAfter: string | null;
  issuer: string | null;
  serialNumber: string | null;
  certStatus: string | null;
  inUseBy: string[];
  subjectDn: string | null;
  sanDomains: string[];
  keyUsage: string | null;
  extendedKeyUsage: string | null;
  certType: string | null;
  managed: boolean | null;
  /**
   * When `managed` is true, the xref of the CertPing certificate this discovered cert
   * maps to, used to deep-link the row to that certificate's detail page. Null/absent
   * for external certs or when the match can no longer be resolved.
   */
  managedCertificateXref?: string | null;
  /**
   * The xref of the deployment credential that discovered this certificate (from the most
   * recent observation), so the Source column can show and deep-link to that credential.
   * Null/absent when no observation can be resolved.
   */
  credentialXref?: string | null;
  /** PRESENT, MISSING or UNKNOWN (server DiscoveredCertDto.inventoryStatus); absent on older servers. */
  inventoryStatus?: DiscoveryInventoryStatus | null;
  discoveredAt: string;
}

/**
 * Whether a discovered cert is still present in the latest relevant scan scope.
 * Mirrors the backend `DiscoveryInventoryStatus`.
 */
export type DiscoveryInventoryStatus = "PRESENT" | "MISSING" | "UNKNOWN";

/** The Kubernetes object that holds the certificate (TLS Secret or inline Route cert). */
export interface KubernetesDiscoverySource {
  apiVersion: string | null;
  kind: string | null;
  namespace: string | null;
  name: string | null;
  uid: string | null;
  resourceVersion: string | null;
  type: string | null;
  fingerprintSha256: string | null;
}

export interface KubernetesBackendService {
  namespace: string | null;
  name: string | null;
  portName: string | null;
  portNumber: number | null;
}

export interface KubernetesAffectedWorkload {
  apiVersion: string | null;
  kind: string | null;
  namespace: string | null;
  name: string | null;
  containers: string[];
  referencePath: string | null;
}

/** A Kubernetes resource that references/uses the discovered certificate. */
export interface KubernetesUsage {
  apiVersion: string | null;
  kind: string | null;
  namespace: string | null;
  name: string | null;
  uid: string | null;
  fieldPath: string | null;
  usageType: string | null;
  hostnames: string[];
  backendServices: KubernetesBackendService[];
  affectedWorkloads: KubernetesAffectedWorkload[];
  confidence: string | null;
}

/** Aggregated business/operational impact of the certificate within the cluster. */
export interface KubernetesImpact {
  externallyServed: boolean | null;
  directlyMountedByWorkloads: boolean | null;
  affectedHostnames: string[];
  affectedServices: string[];
  affectedWorkloads: string[];
  summary: string | null;
}

/**
 * Provider-specific discovery detail for Kubernetes targets. Mirrors the backend
 * `KubernetesDiscoveryData`. Returned in {@link DiscoveredCertDetail.providerData}.
 */
export interface KubernetesDiscoveryData {
  clusterName: string | null;
  usageComplete: boolean | null;
  impactComplete: boolean | null;
  unreadableResourceTypes: string[];
  source: KubernetesDiscoverySource | null;
  usages: KubernetesUsage[];
  impact: KubernetesImpact | null;
  warnings: string[];
}

/**
 * Full detail of a single discovered certificate. Mirrors the backend
 * `DiscoveredCertDetailDto`: the common list fields plus inventory status and an
 * optional provider-specific `providerData` (currently rich only for Kubernetes;
 * null for AWS ACM / Azure KV).
 */
export interface DiscoveredCertDetail {
  id: number;
  organizationId: number;
  targetType: string;
  resourceId: string;
  domain: string | null;
  keyAlgorithm: string | null;
  signatureAlgorithm: string | null;
  notBefore: string | null;
  notAfter: string | null;
  issuer: string | null;
  serialNumber: string | null;
  certStatus: string | null;
  inUseBy: string[];
  subjectDn: string | null;
  sanDomains: string[];
  keyUsage: string | null;
  extendedKeyUsage: string | null;
  certType: string | null;
  inventoryStatus: DiscoveryInventoryStatus | null;
  missingSince: string | null;
  managed: boolean | null;
  discoveredAt: string;
  providerData: KubernetesDiscoveryData | null;
}

export interface DiscoveredCertPage {
  content: DiscoveredCert[];
  totalElements: number;
  totalPages: number;
  number: number;
  size: number;
}

export interface DiscoveryFilters {
  domain?: string;
  targetType?: string;
  keyAlgorithm?: string;
  certStatus?: string;
  managed?: boolean;
  expiresWithinDays?: number;
  page?: number;
  size?: number;
}

/**
 * Lifecycle status of a saved discovery configuration. Mirrors the backend
 * `DiscoveryConfigStatus` enum.
 */
export type DiscoveryConfigStatus =
  | "READY"
  | "STARTED"
  | "IN_PROGRESS"
  | "COMPLETE"
  | "FAILED"
  | "CONFIG_REQUIRED"
  | "CREDENTIAL_INVALID"
  /** The last run was cancelled (by an admin, or by turning discovery off). */
  | "CANCELLED"
  /**
   * The last run finished but some scopes (accounts, regions, vaults,
   * namespaces) could not be read; certificates in them were left unchanged.
   */
  | "PARTIAL";

/** Kinds of scope a discovery scan can fail on (agent `DiscoveryFailedScope.ScopeType`). */
export type DiscoveryFailedScopeType =
  | "AWS_ACCOUNT"
  | "AWS_REGION"
  | "AZURE_VAULT"
  | "K8S_NAMESPACE"
  | "K8S_CLUSTER";

/**
 * One part of a scan the agent could not read. Mirrors the server's
 * messaging/model/DiscoveryFailedScope: all four fields are strings and may be
 * null (an unreadable stored list arrives as scopeType "UNREADABLE" with no id).
 */
export interface DiscoveryFailedScope {
  scopeType: DiscoveryFailedScopeType | string | null;
  /** Account id, "account/region" (or just a region), vault name, namespace or cluster name. */
  scopeId?: string | null;
  errorCode?: string | null;
  message?: string | null;
}

/**
 * Result of triggering, polling, or rerunning a discovery configuration.
 * Mirrors the backend `DiscoveryRunResponse`. `configId` is the stable handle
 * used to poll, rerun, or delete the saved config.
 */
export interface DiscoveryRunResponse {
  configId: number | null;
  status: DiscoveryConfigStatus;
  message: string;
  requestId: string | null;
  targetType: string;
  credentialXref: string | null;
  startedAt: string | null;
  completedAt: string | null;
  /** Present on a PARTIAL run when the server returns it; absent on older servers. */
  failedScopes?: DiscoveryFailedScope[] | null;
}

/** @deprecated Use {@link DiscoveryRunResponse}; kept as an alias for existing callers. */
export type TriggerDiscoveryResult = DiscoveryRunResponse;
