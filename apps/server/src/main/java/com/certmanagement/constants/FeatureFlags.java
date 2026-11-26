// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.constants;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Compile-time constants for all feature flag keys.
 * Each constant matches the {@code feature_key} value seeded in {@code global_feature_flags}.
 *
 * <p>Keys are bare identifiers — scope and category metadata live on the
 * {@code global_feature_flags} row itself, not in the key string.
 *
 * <p>Scope breakdown:
 * <ul>
 *   <li><b>ORG</b>      — SUPER_ADMIN or ORGANIZATION_ADMIN can toggle per org; enforced via
 *       {@link com.certmanagement.annotation.FeatureGated} AOP on JWT-authenticated endpoints.</li>
 *   <li><b>PLATFORM_ONLY</b> — SUPER_ADMIN global toggle only; background jobs declare which of
 *       these they obey in {@link com.certmanagement.service.scheduler.JobPolicy}.</li>
 *   <li><b>SUPER_ADMIN_ONLY</b> — SUPER_ADMIN global toggle only, compliance-sensitive.</li>
 * </ul>
 */
public final class FeatureFlags {

    private FeatureFlags() {}

    // ── ORG scope: functional features ───────────────────────────────────

    public static final String CERTIFICATE_ISSUANCE        = "CERTIFICATE_ISSUANCE";
    public static final String CERTIFICATE_MANUAL_ISSUANCE = "CERTIFICATE_MANUAL_ISSUANCE";
    public static final String CERTIFICATE_RENEWAL         = "CERTIFICATE_RENEWAL";
    public static final String CERTIFICATE_DEPLOYMENT      = "CERTIFICATE_DEPLOYMENT";
    public static final String CERTIFICATE_REVOCATION      = "CERTIFICATE_REVOCATION";
    /** Download of certificates the platform stores, whatever their CA — PLATFORM category */
    public static final String CERTIFICATE_DOWNLOAD        = "CERTIFICATE_DOWNLOAD";
    public static final String CREDENTIALS_MANAGEMENT      = "CREDENTIALS_MANAGEMENT";
    public static final String ALERTS                      = "ALERTS";
    public static final String AGENT_HEALTH_MONITORING     = "AGENT_HEALTH_MONITORING";
    /** IoT device identity registration from an MDM — B2B category */
    public static final String IOT_DEVICE_MANAGEMENT       = "IOT_DEVICE_MANAGEMENT";
    public static final String IOT_PROVIDER_INTUNE         = "IOT_PROVIDER_INTUNE";
    public static final String IOT_CERTIFICATE_PROFILE_MANAGEMENT =
            "IOT_CERTIFICATE_PROFILE_MANAGEMENT";
    /** PQC readiness report and CBOM download — PLATFORM category */
    public static final String PQC_READINESS               = "PQC_READINESS";
    /** Certificate discovery across cloud targets (scans, results, saved configs) — PLATFORM category */
    public static final String DISCOVERY                   = "DISCOVERY";
    /** Add, edit and remove DNS provider credentials; off also holds the renewals that use them — PLATFORM category */
    public static final String DNS_CREDENTIALS             = "DNS_CREDENTIALS";
    /** Slack, Teams, PagerDuty and ServiceNow integrations, incidents and their delivery — PLATFORM category */
    public static final String INTEGRATIONS                = "INTEGRATIONS";
    /** The organization feature flags page and its writes; {@code /effective} stays open — PLATFORM category */
    public static final String FEATURE_FLAGS_PAGE          = "FEATURE_FLAGS_PAGE";
    /** Organization admins may turn off informational notification categories — PLATFORM category */
    public static final String NOTIFICATION_PREFERENCES    = "NOTIFICATION_PREFERENCES";

    // ── ORG scope: IoT SCEP CA provider flags ────────────────────────────
    // Unrelated to the "CA provider flags" section below, which gates the SSL/domain-certificate
    // issuance CAs. These gate IoT device-certificate SCEP connectors reported via
    // iot_ca_health_status, independently of each other and of IOT_DEVICE_MANAGEMENT.

    /** EJBCA IoT SCEP connector — gates its health/connector visibility independently of Smallstep. */
    public static final String CA_EJBCA     = "CA_EJBCA";
    /** Smallstep (step-ca) IoT SCEP connector — gates its health/connector visibility independently of EJBCA. */
    public static final String CA_SMALLSTEP = "CA_SMALLSTEP";

    // ── ORG scope: CA provider flags ─────────────────────────────────────

    /** Let's Encrypt / ACME — PLATFORM category */
    public static final String CA_LETS_ENCRYPT = "LETS_ENCRYPT";
    /** DigiCert — PLATFORM category */
    public static final String CA_DIGICERT     = "DIGICERT";
    /** GlobalSign — PLATFORM category */
    public static final String CA_GLOBALSIGN   = "GLOBALSIGN";

    // ── PLATFORM scope: scheduler jobs ───────────────────────────────────
    //
    // Convention: each background job names its kill switch (one of these) in
    // JobPolicy, and SchedulerExecutionPolicy.canRun checks it with orgId=null
    // after the static enable-property guard. Passing null as orgId means only
    // the global kill switch applies: these are platform-level toggles, not per-org.
    //
    // Cron flags are kept SEPARATE from the corresponding user-facing feature
    // flag (e.g. AUTO_RENEWAL is distinct from CERTIFICATE_RENEWAL) so that ops
    // can pause a cron during an incident (a CA outage causing the renewal loop
    // to hammer a broken API) without taking down the user-facing UI/API for the
    // same feature.
    //
    // SOFT_DELETE_PURGE is compliance-sensitive: turning it off halts the
    // nightly hard-delete sweep, which can put retention SLAs out of compliance
    // if left off indefinitely. Treat changes here as audited operations.

    public static final String AUTO_RENEWAL             = "AUTO_RENEWAL";
    public static final String EXPIRY_ALERTS            = "EXPIRY_ALERTS";
    public static final String EXPIRY_MARKING           = "EXPIRY_MARKING";
    public static final String EXPIRED_CERT_SOFT_DELETE = "EXPIRED_CERT_SOFT_DELETE";
    public static final String SOFT_DELETE_PURGE        = "SOFT_DELETE_PURGE";
    public static final String QUEUE_DEPTH_ALERTS       = "QUEUE_DEPTH_ALERTS";
    /**
     * Ops switch for the feature lifecycle's baseline and backstop sweep (seeded off). Forced
     * transitions from a super admin's flag change are applied whatever it says.
     */
    public static final String FEATURE_LIFECYCLE_RECONCILE = "FEATURE_LIFECYCLE_RECONCILE";
    /**
     * Ops switch for the audit retention job, which drops audit-event months older than the
     * {@code audit_retention_months} setting (seeded on). COMPLIANCE-SENSITIVE like
     * SOFT_DELETE_PURGE: off keeps audit data, IP addresses included, past its retention period.
     */
    public static final String AUDIT_RETENTION_PURGE = "AUDIT_RETENTION_PURGE";

    // ── PLATFORM scope: compliance-sensitive admin flags ─────────────────

    public static final String AUDIT_LOGS = "AUDIT_LOGS";

    /**
     * ORG-scope flags that only a SUPER_ADMIN decides per organization. An org admin can neither set
     * nor remove an override for them. FEATURE_FLAGS_PAGE: an org admin who switched it off would lock
     * themselves out of the page that switches it back on. NOTIFICATION_PREFERENCES: whether an
     * organization may turn notifications off is CertPing's decision in every deployment.
     */
    public static final Set<String> NOT_ORG_CONTROLLABLE =
            Set.of(FEATURE_FLAGS_PAGE, NOTIFICATION_PREFERENCES);

    /**
     * The flag each feature's automatic work also needs, beyond its own: automatic renewal runs only
     * while DNS credentials are on. The feature itself (a manual "Renew now", its permission) follows
     * its own decision alone.
     */
    public static final Map<String, String> AUTOMATIC_WORK_REQUIRES = Map.of(CERTIFICATE_RENEWAL, DNS_CREDENTIALS);

    /** The flags that decide whether {@code featureKey}'s automatic work runs: itself and its requirement. */
    public static List<String> automaticWorkKeys(String featureKey) {
        String requiredKey = AUTOMATIC_WORK_REQUIRES.get(featureKey);
        return requiredKey == null ? List.of(featureKey) : List.of(featureKey, requiredKey);
    }

    /** What a caller is told when DNS credentials are off for their organization. */
    public static final String DNS_CREDENTIALS_UNAVAILABLE = "DNS credentials aren't available. Ask your CertPing administrator.";

    /** What a caller is told when the feature flags page is off for their organization. */
    public static final String FEATURE_FLAGS_UNAVAILABLE = "Feature flags aren't available. Ask your CertPing administrator.";

    /** What a caller is told when notification settings are off for their organization. */
    public static final String NOTIFICATION_SETTINGS_UNAVAILABLE =
            "Notification settings aren't available. Ask your CertPing administrator.";
}
