// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Every feature-flag key the backend defines, mirroring
 * `com.certmanagement.constants.FeatureFlags`.
 *
 * <p>Flag keys used to live as bare strings at each call site, which made two
 * questions unanswerable without reading the backend: which flags exist, and
 * which ones this app actually gates on. Both matter, because a flag the
 * frontend ignores is still enforced server-side - the endpoint returns `423`
 * and the UI has to explain which capability is off.
 *
 * <p>Grouped by the backend's scopes. `ORG` flags an organization admin may
 * switch; `PLATFORM` flags only a super admin may. UI gates read the
 * effective map (`GET /feature-flags/effective`), which resolves every flag of
 * both scopes for the current organization. The settings page's own
 * `GET /feature-flags` lists what the org admin can switch, plus the flags
 * managed by CertPing (read-only), and never feeds a gate.
 */

export const FEATURE_FLAGS = {
  // ── ORG scope: certificate lifecycle ────────────────────────────────
  CERTIFICATE_ISSUANCE: "CERTIFICATE_ISSUANCE",
  CERTIFICATE_MANUAL_ISSUANCE: "CERTIFICATE_MANUAL_ISSUANCE",
  CERTIFICATE_RENEWAL: "CERTIFICATE_RENEWAL",
  CERTIFICATE_DEPLOYMENT: "CERTIFICATE_DEPLOYMENT",
  CERTIFICATE_REVOCATION: "CERTIFICATE_REVOCATION",
  CREDENTIALS_MANAGEMENT: "CREDENTIALS_MANAGEMENT",
  /** Adding, editing and removing DNS provider credentials. */
  DNS_CREDENTIALS: "DNS_CREDENTIALS",
  /** Gates the Cryptography page: PQC readiness report and CBOM download. */
  PQC_READINESS: "PQC_READINESS",
  /** Gates certificate discovery: scans, results, and their routes. */
  DISCOVERY: "DISCOVERY",
  /** Gates exporting certificates held in the CertPing vault, from any CA. */
  CERTIFICATE_DOWNLOAD: "CERTIFICATE_DOWNLOAD",

  // ── ORG scope: platform surfaces ────────────────────────────────────
  ALERTS: "ALERTS",
  AGENT_HEALTH_MONITORING: "AGENT_HEALTH_MONITORING",
  /** Chat and paging integrations, incident escalations and their delivery. */
  INTEGRATIONS: "INTEGRATIONS",
  /** The organization feature flags page and its writes. */
  FEATURE_FLAGS_PAGE: "FEATURE_FLAGS_PAGE",
  /** Whether organization admins may turn informational notifications off; only CertPing decides. */
  NOTIFICATION_PREFERENCES: "NOTIFICATION_PREFERENCES",

  // ── ORG scope: machine identity ─────────────────────────────────────
  IOT_DEVICE_MANAGEMENT: "IOT_DEVICE_MANAGEMENT",
  IOT_PROVIDER_INTUNE: "IOT_PROVIDER_INTUNE",
  IOT_CERTIFICATE_PROFILE_MANAGEMENT: "IOT_CERTIFICATE_PROFILE_MANAGEMENT",
  /** Gates the EJBCA SCEP connector's visibility, independently of Smallstep. */
  CA_EJBCA: "CA_EJBCA",
  /** Gates the Smallstep SCEP connector's visibility, independently of EJBCA. */
  CA_SMALLSTEP: "CA_SMALLSTEP",

  // ── ORG scope: SSL certificate authorities ──────────────────────────
  LETS_ENCRYPT: "LETS_ENCRYPT",
  DIGICERT: "DIGICERT",
  GLOBALSIGN: "GLOBALSIGN",

  // ── PLATFORM scope: operator kill switches ──────────────────────────
  AUDIT_LOGS: "AUDIT_LOGS",
  AUTO_RENEWAL: "AUTO_RENEWAL",
  EXPIRY_ALERTS: "EXPIRY_ALERTS",
  EXPIRY_MARKING: "EXPIRY_MARKING",
  ISSUANCE_RETRY: "ISSUANCE_RETRY",
  EXPIRED_CERT_SOFT_DELETE: "EXPIRED_CERT_SOFT_DELETE",
  SOFT_DELETE_PURGE: "SOFT_DELETE_PURGE",
  QUEUE_DEPTH_ALERTS: "QUEUE_DEPTH_ALERTS",
  GOOGLE_OAUTH: "GOOGLE_OAUTH",
  GITHUB_OAUTH: "GITHUB_OAUTH",
  MICROSOFT_OAUTH: "MICROSOFT_OAUTH",
  LINKEDIN_OAUTH: "LINKEDIN_OAUTH",
} as const;

export type FeatureFlagKey = (typeof FEATURE_FLAGS)[keyof typeof FEATURE_FLAGS];

/**
 * Product names for flag keys, used when an endpoint answers `423` and the UI
 * has to say which capability is off. Only keys whose product name differs
 * from a plain de-underscored reading need an entry.
 */
const FEATURE_FLAG_LABELS: Partial<Record<FeatureFlagKey, string>> = {
  CERTIFICATE_ISSUANCE: "Certificate issuance",
  CERTIFICATE_MANUAL_ISSUANCE: "Manual certificate issuance",
  CERTIFICATE_RENEWAL: "Certificate renewal",
  CERTIFICATE_DEPLOYMENT: "Certificate deployment",
  CERTIFICATE_REVOCATION: "Certificate revocation",
  CREDENTIALS_MANAGEMENT: "Credential management",
  DNS_CREDENTIALS: "DNS credentials",
  PQC_READINESS: "PQC readiness",
  DISCOVERY: "Certificate discovery",
  CERTIFICATE_DOWNLOAD: "Certificate download",
  AGENT_HEALTH_MONITORING: "Agent health monitoring",
  INTEGRATIONS: "Integrations",
  FEATURE_FLAGS_PAGE: "Feature flags page",
  NOTIFICATION_PREFERENCES: "Notification settings page",
  IOT_DEVICE_MANAGEMENT: "Machine Identity",
  IOT_PROVIDER_INTUNE: "Microsoft Intune integration",
  IOT_CERTIFICATE_PROFILE_MANAGEMENT: "Certificate profiles",
  CA_EJBCA: "EJBCA",
  CA_SMALLSTEP: "Smallstep",
  LETS_ENCRYPT: "Let's Encrypt",
  DIGICERT: "DigiCert",
  GLOBALSIGN: "GlobalSign",
  AUDIT_LOGS: "Audit logs",
};

/**
 * Product name for a flag key. Falls back to a readable rendering of the key
 * itself, so a flag added to the backend before this catalogue still produces
 * a sentence rather than a raw constant.
 */
export function featureFlagLabel(featureKey: string | undefined): string {
  if (!featureKey) return "This feature";
  const known = FEATURE_FLAG_LABELS[featureKey as FeatureFlagKey];
  if (known) return known;
  const words = featureKey.replaceAll("_", " ").toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Resolved on/off state of every flag, ORG and PLATFORM, for the current organization. */
export type EffectiveFlagMap = Readonly<Record<string, boolean>>;
