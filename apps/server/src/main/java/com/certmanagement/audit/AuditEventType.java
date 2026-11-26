// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.ResourceType;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.certmanagement.audit.AuditCategory.ACCESS;
import static com.certmanagement.audit.AuditCategory.ACCESS_CONTROL;
import static com.certmanagement.audit.AuditCategory.AUTHENTICATION;
import static com.certmanagement.audit.AuditCategory.CERTIFICATES;
import static com.certmanagement.audit.AuditCategory.CREDENTIALS;
import static com.certmanagement.audit.AuditCategory.DEPLOYMENTS;
import static com.certmanagement.audit.AuditCategory.DISCOVERY;
import static com.certmanagement.audit.AuditCategory.INTEGRATIONS;
import static com.certmanagement.audit.AuditCategory.MACHINE_IDENTITY;
import static com.certmanagement.audit.AuditCategory.MONITORING;
import static com.certmanagement.audit.AuditCategory.ORGANIZATION;
import static com.certmanagement.audit.AuditCategory.PLATFORM;
import static com.certmanagement.audit.AuditCategory.SUPPORT;
import static com.certmanagement.audit.AuditSensitivity.CHANGE;
import static com.certmanagement.audit.AuditVisibility.CUSTOMER;
import static com.certmanagement.audit.AuditVisibility.INTERNAL;

/**
 * The catalog of audit events: every row's {@code event} is one of these keys. Each entry fixes the
 * row's visibility, category, action code, resource type, owning feature flag ({@code null} for core
 * events that are always shown), sensitivity, the attribute names it may carry, and the sentence it
 * reads as when it succeeded and when it failed.
 *
 * <p>The sentences take an {@link AuditSubject} and must read sensibly with any of its fields missing.
 * They never include an error's text: a failure's cause is the row's {@link AuditReason} code, rendered
 * when read.
 *
 * <p>Member-targeted events ({@link ResourceType#USER}) never store the member's name: the summary is
 * stored with "a member" in its place and {@code resource_name} stays empty, and the read side renders
 * it again with the member's current name ({@link #rendersTargetWhenRead()}). A GDPR erasure of the
 * member then needs no change to the rows about them; only the rows they acted in carry their name,
 * as {@code actor_label}, which the append-only trigger lets an erasure pseudonymise.
 */
public enum AuditEventType {

    // ── Access control (core) ────────────────────────────────────────────
    // A member's email and name are personal: a change to them is stored as the field name alone.
    // Member events render from the member placeholder and attributes only (rendersTargetWhenRead).
    MEMBER_CREATED("member.created", CUSTOMER, ACCESS_CONTROL, "USER_CREATED", ResourceType.USER, null,
            Allowed.NONE.attributes("source", "authMethod", "provider").changes("roles")
                    .personal("email", "name", "displayName"),
            s -> "Added " + member(s),
            s -> "Could not add " + member(s)),
    MEMBER_ENABLED("member.enabled", CUSTOMER, ACCESS_CONTROL, "USER_ENABLED", ResourceType.USER, null,
            Allowed.NONE.attributes("source", "provider"),
            s -> "Re-enabled " + member(s),
            s -> "Could not re-enable " + member(s)),
    MEMBER_DISABLED("member.disabled", CUSTOMER, ACCESS_CONTROL, "USER_DISABLED", ResourceType.USER, null,
            Allowed.NONE.attributes("source", "roles"),
            s -> "Disabled " + member(s),
            s -> "Could not disable " + member(s)),
    MEMBER_DELETED("member.deleted", CUSTOMER, ACCESS_CONTROL, "USER_DELETED", ResourceType.USER, null,
            Allowed.NONE.attributes("roles"),
            s -> "Removed " + member(s),
            s -> "Could not remove " + member(s)),
    MEMBER_EMAIL_CHANGED("member.email_changed", CUSTOMER, ACCESS_CONTROL, "USER_EMAIL_CHANGED", ResourceType.USER,
            null, Allowed.NONE.personal("email"),
            s -> "Changed " + member(s) + "'s email",
            s -> "Could not change " + member(s) + "'s email"),
    // A platform super admin chose the organization they work in; the row lands in that organization's trail.
    MEMBER_ORGANIZATION_CHANGED("member.organization_changed", CUSTOMER, ACCESS_CONTROL, "USER_ORGANIZATION_CHANGED",
            ResourceType.USER, null, Allowed.NONE,
            s -> member(s) + " now works in this organization",
            s -> "Could not move " + member(s) + " into this organization"),
    MEMBER_MFA_RESET("member.mfa_reset", CUSTOMER, ACCESS_CONTROL, "USER_MFA_RESET", ResourceType.USER, null,
            Allowed.NONE,
            s -> "Reset " + member(s) + "'s two-factor authentication",
            s -> "Could not reset " + member(s) + "'s two-factor authentication"),
    MEMBER_ROLES_CHANGED("member.roles_changed", CUSTOMER, ACCESS_CONTROL, "USER_ROLES_CHANGED", ResourceType.USER,
            null, Allowed.NONE.changes("roles").attributes("added", "removed", "droppedDirectPermissions"),
            s -> "Changed " + member(s) + "'s roles",
            s -> "Could not change " + member(s) + "'s roles"),
    MEMBER_PERMISSIONS_CHANGED("member.permissions_changed", CUSTOMER, ACCESS_CONTROL, "USER_PERMISSIONS_CHANGED",
            ResourceType.USER, null, Allowed.NONE.changes("permissions").attributes("added", "removed"),
            s -> "Changed " + member(s) + "'s permissions",
            s -> "Could not change " + member(s) + "'s permissions"),
    MEMBER_SSO_ROLES_ASSIGNED("member.sso_roles_assigned", CUSTOMER, ACCESS_CONTROL, "SSO_ROLES_ASSIGNED",
            ResourceType.USER, null, Allowed.NONE.changes("roles").attributes("source", "registrationId"),
            s -> "Single sign-on assigned roles to " + member(s),
            s -> "Single sign-on could not assign roles to " + member(s)),
    // Written as a failure only: a member change refused before it was known which of its fields would
    // change (the email, the active flag). A change that happens is recorded as the event it was.
    MEMBER_UPDATED("member.updated", CUSTOMER, ACCESS_CONTROL, "USER_UPDATED", ResourceType.USER, null,
            Allowed.NONE,
            s -> "Changed " + member(s) + "'s details",
            s -> "Could not change " + member(s) + "'s details"),
    ROLE_CREATED("role.created", CUSTOMER, ACCESS_CONTROL, "ROLE_CREATED", ResourceType.ROLE, null,
            Allowed.NONE.changes("permissions"),
            s -> "Created the role" + quoted(s.name()),
            s -> "Could not create the role" + quoted(s.name())),
    ROLE_DELETED("role.deleted", CUSTOMER, ACCESS_CONTROL, "ROLE_DELETED", ResourceType.ROLE, null,
            Allowed.NONE.attributes("permissions", "unassignedMembers"),
            s -> "Deleted the role" + quoted(s.name()),
            s -> "Could not delete the role" + quoted(s.name())),
    ROLE_PERMISSIONS_CHANGED("role.permissions_changed", CUSTOMER, ACCESS_CONTROL, "ROLE_PERMISSIONS_CHANGED",
            ResourceType.ROLE, null, Allowed.NONE.changes("permissions").attributes("added", "removed"),
            s -> "Changed the permissions of the role" + quoted(s.name()),
            s -> "Could not change the permissions of the role" + quoted(s.name())),

    // ── Sign-in (core) ───────────────────────────────────────────────────
    // The actor is the account signing in, signing out or resetting its password (AuditScope.user). The
    // identifier someone typed is never stored: a failure names a known account by its actor id only, and
    // one for an identifier no account has is kept as an internal anonymous row (AuthAuditRecorder).
    // A platform staff account's rows are internal (AuditEvents.platformOnly): staff have no customer trail.
    AUTH_SIGNED_IN("auth.signed_in", CUSTOMER, AUTHENTICATION, "SIGN_IN", ResourceType.AUTH, null,
            Allowed.NONE.attributes("method", "registrationId"),
            s -> "Signed in" + signInMethod(s),
            s -> "Could not sign in" + signInMethod(s)),
    // Written as a failure only (AuditEvents.failure); the success sentence is never stored.
    AUTH_SIGN_IN_FAILED("auth.sign_in_failed", CUSTOMER, AUTHENTICATION, "SIGN_IN", ResourceType.AUTH, null,
            Allowed.NONE.attributes("method", "registrationId"),
            s -> "Could not sign in" + signInMethod(s),
            s -> "Could not sign in" + signInMethod(s)),
    AUTH_SIGNED_OUT("auth.signed_out", CUSTOMER, AUTHENTICATION, "SIGN_OUT", ResourceType.AUTH, null,
            Allowed.NONE,
            s -> "Signed out",
            s -> "Could not sign out"),
    AUTH_PASSWORD_CHANGED("auth.password_changed", CUSTOMER, AUTHENTICATION, "PASSWORD_CHANGE", ResourceType.AUTH,
            null, Allowed.NONE,
            s -> "Changed their password",
            s -> "Could not change their password"),
    AUTH_MFA_ENABLED("auth.mfa_enabled", CUSTOMER, AUTHENTICATION, "MFA_ENABLE", ResourceType.AUTH, null,
            Allowed.NONE,
            s -> "Turned on two-factor authentication",
            s -> "Could not turn on two-factor authentication"),
    AUTH_MFA_DISABLED("auth.mfa_disabled", CUSTOMER, AUTHENTICATION, "MFA_DISABLE", ResourceType.AUTH, null,
            Allowed.NONE,
            s -> "Turned off two-factor authentication",
            s -> "Could not turn off two-factor authentication"),
    AUTH_PASSWORD_RESET_REQUESTED("auth.password_reset_requested", CUSTOMER, AUTHENTICATION,
            "PASSWORD_RESET_REQUEST", ResourceType.AUTH, null, Allowed.NONE,
            s -> "Requested a password reset email",
            s -> "Could not request a password reset email"),
    AUTH_PASSWORD_RESET_COMPLETED("auth.password_reset_completed", CUSTOMER, AUTHENTICATION, "PASSWORD_RESET",
            ResourceType.AUTH, null, Allowed.NONE,
            s -> "Reset their password with an emailed link",
            s -> "Could not reset their password"),
    // CertPing (AuditScope.system) locked a member's password sign-in after too many failed attempts. The
    // member is the target, rendered from the live users row when read; the attempt count is the attribute.
    // Customer accounts only: a staff lockout is an ERROR log line and the certping.auth.lockouts metric.
    AUTH_ACCOUNT_LOCKED("auth.account_locked", CUSTOMER, AUTHENTICATION, "ACCOUNT_LOCK", ResourceType.USER, null,
            Allowed.NONE.attributes("attempts"),
            s -> member(s) + "'s account was locked after " + failedSignIns(s),
            s -> "Could not lock " + member(s) + "'s account"),

    // ── Organization (core) ──────────────────────────────────────────────
    ORGANIZATION_CREATED("organization.created", CUSTOMER, ORGANIZATION, "CREATE", ResourceType.ORGANIZATION, null,
            Allowed.NONE.attributes("source"),
            s -> "Created the organization",
            s -> "Could not create the organization"),
    // The organization's name is never stored (it is rendered live): a rename is kept by field name only.
    ORGANIZATION_UPDATED("organization.updated", CUSTOMER, ORGANIZATION, "UPDATE", ResourceType.ORGANIZATION, null,
            Allowed.NONE.changes("domain", "active").personal("name"),
            s -> "Changed the organization's settings",
            s -> "Could not change the organization's settings"),
    ORGANIZATION_DELETED("organization.deleted", CUSTOMER, ORGANIZATION, "DELETE", ResourceType.ORGANIZATION, null,
            Allowed.NONE,
            s -> "Deleted the organization",
            s -> "Could not delete the organization"),
    FEATURE_CHANGED("feature.changed", CUSTOMER, ORGANIZATION, "FEATURE_FLAG_CHANGED", ResourceType.FEATURE_FLAG,
            null, Allowed.NONE.changes("enabled", "adminLocked").attributes("level", "orgType")
                    .internalOnly("reason"),
            s -> (s.enabled() == null ? "Changed" : s.isEnabled() ? "Turned on" : "Turned off")
                    + " the feature" + quoted(s.name()),
            s -> "Could not change the feature" + quoted(s.name())),
    FEATURE_OVERRIDE_REMOVED("feature.override_removed", CUSTOMER, ORGANIZATION, "FEATURE_FLAG_OVERRIDE_REMOVED",
            ResourceType.FEATURE_FLAG, null, Allowed.NONE.attributes("level", "orgType").internalOnly("reason"),
            s -> "Removed the override of the feature" + quoted(s.name()),
            s -> "Could not remove the override of the feature" + quoted(s.name())),
    FEATURE_RECORDS_CLEARED("feature.records_cleared", CUSTOMER, ORGANIZATION, "FEATURE_CLEARED",
            ResourceType.FEATURE_FLAG, null, Allowed.NONE.attributes("kind", "action"),
            s -> "Cleared " + records(s) + " of the feature" + quoted(s.name()),
            s -> "Could not clear " + records(s) + " of the feature" + quoted(s.name())),
    FEATURE_PAUSED("feature.paused", CUSTOMER, ORGANIZATION, "FEATURE_PLATFORM_PAUSED", ResourceType.FEATURE_FLAG,
            null, Allowed.NONE.attributes("items", "cause", "requestedBy"),
            s -> "Paused " + records(s) + " because the feature" + quoted(s.name()) + " was turned off",
            s -> "Could not pause " + records(s) + " of the feature" + quoted(s.name())),
    FEATURE_RESUMED("feature.resumed", CUSTOMER, ORGANIZATION, "FEATURE_PLATFORM_RESUMED", ResourceType.FEATURE_FLAG,
            null, Allowed.NONE.attributes("items", "requestedBy"),
            s -> "Resumed " + records(s) + " because the feature" + quoted(s.name()) + " was turned on",
            s -> "Could not resume " + records(s) + " of the feature" + quoted(s.name())),
    // Removed (soft-deleted) records are kept for a retention period, then permanently deleted.
    DATA_RETENTION_PURGED("data_retention.purged", CUSTOMER, ORGANIZATION, "PURGE", ResourceType.ORGANIZATION, null,
            Allowed.NONE.attributes("retentionDays"),
            s -> "Permanently deleted " + records(s) + " removed" + olderThan(s),
            s -> "Could not permanently delete the records removed" + olderThan(s)),
    DATA_RETENTION_CHANGED("data_retention.changed", CUSTOMER, ORGANIZATION, "RETENTION_CHANGE",
            ResourceType.ORGANIZATION, null, Allowed.NONE.changes("retentionDays"),
            s -> "Changed how long removed records are kept",
            s -> "Could not change how long removed records are kept"),
    // The informational notification categories an organization's admins turned off (NotificationCategory names).
    NOTIFICATION_SETTINGS_CHANGED("notification_settings.changed", CUSTOMER, ORGANIZATION,
            "NOTIFICATION_SETTINGS_CHANGE", ResourceType.ORGANIZATION, null, Allowed.NONE.changes("mutedCategories"),
            s -> "Changed which notifications are sent",
            s -> "Could not change which notifications are sent"),
    // An export of the trail (AuditTrailExporter), written before any of its rows are read: the export does not
    // start unless this row is on record. A refused export (too many rows) is a failure row; both count toward the
    // organization's exports per hour. The range and format are attributes; the rows themselves never are.
    AUDIT_LOG_EXPORTED("audit_log.exported", CUSTOMER, ORGANIZATION, "DATA_EXPORT", ResourceType.AUDIT, null,
            Allowed.NONE.attributes("from", "to", "format"),
            s -> "Exported " + entries(s, "audit log") + as(s.format()),
            s -> "Could not export the audit log" + as(s.format())),
    ACCESS_LOG_EXPORTED("access_log.exported", CUSTOMER, ORGANIZATION, "DATA_EXPORT", ResourceType.AUDIT, null,
            Allowed.NONE.attributes("from", "to", "format"),
            s -> "Exported " + entries(s, "access log") + as(s.format()),
            s -> "Could not export the access log" + as(s.format())),
    // A platform administrator reading or exporting the organization's trail from the platform view: a staff row written
    // into the customer's trail, read there as "Platform administrator" with nothing of who or from where. Views are
    // grouped to one row per organization and staff member every 15 minutes (AuditedReads); every export is a row.
    SUPPORT_AUDIT_LOG_VIEWED("support.audit_log_viewed", CUSTOMER, ORGANIZATION, "VIEW", ResourceType.AUDIT, null,
            Allowed.NONE,
            s -> "Viewed the audit log",
            s -> "Could not view the audit log"),
    SUPPORT_AUDIT_LOG_EXPORTED("support.audit_log_exported", CUSTOMER, ORGANIZATION, "DATA_EXPORT",
            ResourceType.AUDIT, null, Allowed.NONE.attributes("from", "to", "format"),
            s -> "Exported " + entries(s, "audit log") + as(s.format()),
            s -> "Could not export the audit log" + as(s.format())),

    // ── Certificates ─────────────────────────────────────────────────────
    CERTIFICATE_EXPORTED("certificate.exported", CUSTOMER, CERTIFICATES, "EXPORT", ResourceType.CERTIFICATE, null,
            Allowed.NONE.attributes("keyIncluded", "legacyCipher"),
            s -> "Exported the certificate" + named(s.domain()) + as(s.format()),
            s -> "Could not export the certificate" + named(s.domain()) + as(s.format())),
    // The lifecycle of a certificate (CertificateAuditRecorder). A member's request ("…_requested") is the member's
    // row; what the agent then reports ("issued", "renewed", "revoked") is CertPing's (AuditScope.system), carrying
    // the requesting member's id as requestedBy. A failure's cause is its reason code, never the agent's text.
    CERTIFICATE_ISSUE_REQUESTED("certificate.issue_requested", CUSTOMER, CERTIFICATES, "ISSUE_REQUEST",
            ResourceType.CERTIFICATE, FeatureFlags.CERTIFICATE_ISSUANCE,
            Allowed.NONE.attributes("wildcard", "sanDomains", "deploymentTargets"),
            s -> "Requested a certificate" + forDomain(s) + from(s.provider()),
            s -> "Could not request a certificate" + forDomain(s) + from(s.provider())),
    CERTIFICATE_ISSUED("certificate.issued", CUSTOMER, CERTIFICATES, "ISSUE", ResourceType.CERTIFICATE,
            FeatureFlags.CERTIFICATE_ISSUANCE, Allowed.NONE.attributes("requestedBy", "validTo", "special", "flow"),
            s -> "Issued " + certificate(s) + from(s.provider()),
            s -> "Issuing " + certificate(s) + " failed"),
    CERTIFICATE_MANUAL_ISSUE_REQUESTED("certificate.manual_issue_requested", CUSTOMER, CERTIFICATES,
            "MANUAL_ISSUE_REQUEST", ResourceType.CERTIFICATE, FeatureFlags.CERTIFICATE_MANUAL_ISSUANCE,
            Allowed.NONE.attributes("wildcard", "sanDomains"),
            s -> "Started a manual issuance of a certificate" + forDomain(s) + from(s.provider()),
            s -> "Could not start a manual issuance of a certificate" + forDomain(s)),
    CERTIFICATE_DNS_VALIDATED("certificate.dns_validated", CUSTOMER, CERTIFICATES, "DNS_VALIDATE",
            ResourceType.CERTIFICATE, FeatureFlags.CERTIFICATE_MANUAL_ISSUANCE, Allowed.NONE,
            s -> "Confirmed the DNS records" + forDomain(s) + " were added and started validation",
            s -> "Could not start DNS validation" + forDomain(s)),
    CERTIFICATE_RENEWAL_REQUESTED("certificate.renewal_requested", CUSTOMER, CERTIFICATES, "RENEW_REQUEST",
            ResourceType.CERTIFICATE, FeatureFlags.CERTIFICATE_RENEWAL, Allowed.NONE,
            s -> "Requested renewal of " + certificate(s),
            s -> "Could not request renewal of " + certificate(s)),
    CERTIFICATE_AUTO_RENEWAL_STARTED("certificate.auto_renewal_started", CUSTOMER, CERTIFICATES, "AUTO_RENEW",
            ResourceType.CERTIFICATE, FeatureFlags.CERTIFICATE_RENEWAL, Allowed.NONE.attributes("special"),
            s -> "Started renewing " + certificate(s) + " automatically",
            s -> "Could not start renewing " + certificate(s) + " automatically"),
    CERTIFICATE_RENEWED("certificate.renewed", CUSTOMER, CERTIFICATES, "RENEW", ResourceType.CERTIFICATE,
            FeatureFlags.CERTIFICATE_RENEWAL, Allowed.NONE.attributes("requestedBy", "validTo", "replaces"),
            s -> "Renewed " + certificate(s) + from(s.provider()),
            s -> "Renewing " + certificate(s) + " failed"),
    // Written as a failure only, with the reason FEATURE_OFF: automatic renewal did not happen.
    CERTIFICATE_AUTO_RENEWAL_SKIPPED("certificate.auto_renewal_skipped", CUSTOMER, CERTIFICATES, "AUTO_RENEW_SKIP",
            ResourceType.CERTIFICATE, FeatureFlags.CERTIFICATE_RENEWAL,
            Allowed.NONE.attributes("feature", "flow", "plan", "dnsKeyExpiredOn"),
            s -> "Skipped renewing " + certificate(s) + " automatically because " + skipCause(s),
            s -> "Skipped renewing " + certificate(s) + " automatically because " + skipCause(s)),
    CERTIFICATE_REVOKE_REQUESTED("certificate.revoke_requested", CUSTOMER, CERTIFICATES, "REVOKE_REQUEST",
            ResourceType.CERTIFICATE, FeatureFlags.CERTIFICATE_REVOCATION, Allowed.NONE.attributes("revocationReason"),
            s -> "Requested revocation of " + certificate(s),
            s -> "Could not request revocation of " + certificate(s)),
    CERTIFICATE_REVOKED("certificate.revoked", CUSTOMER, CERTIFICATES, "REVOKE", ResourceType.CERTIFICATE,
            FeatureFlags.CERTIFICATE_REVOCATION, Allowed.NONE.attributes("requestedBy", "revocationReason"),
            s -> "Revoked " + certificate(s),
            s -> "Revoking " + certificate(s) + " failed"),
    // Core: certificate:delete is a core permission. "source" says what removed it when it was not the
    // certificate's own delete: MANAGED_DOMAIN (its managed domain was deleted) or EXPIRY_CLEANUP (CertPing).
    CERTIFICATE_DELETED("certificate.deleted", CUSTOMER, CERTIFICATES, "DELETE", ResourceType.CERTIFICATE, null,
            Allowed.NONE.attributes("source", "status"),
            s -> "Deleted " + certificate(s),
            s -> "Could not delete " + certificate(s)),
    CERTIFICATE_CONVERTED_TO_AUTOMATED("certificate.converted_to_automated", CUSTOMER, CERTIFICATES,
            "CONVERT_TO_AUTOMATED", ResourceType.CERTIFICATE, FeatureFlags.CERTIFICATE_ISSUANCE,
            Allowed.NONE.attributes("activationMode", "plannedAction", "deploymentTargets"),
            s -> "Switched " + certificate(s) + " to automatic renewal",
            s -> "Could not switch " + certificate(s) + " to automatic renewal"),
    CERTIFICATE_EXPIRED("certificate.expired", CUSTOMER, CERTIFICATES, "EXPIRE", ResourceType.CERTIFICATE, null,
            Allowed.NONE.attributes("validTo"),
            s -> capitalised(certificate(s)) + " expired",
            s -> "Could not mark " + certificate(s) + " as expired"),

    // ── Deployments ──────────────────────────────────────────────────────
    // A deployment of a certificate to a target (the deployment's type, e.g. "Azure Key Vault"). The row's
    // resource_ref is the certificate's xref, so a certificate's deployments filter with it.
    DEPLOYMENT_REQUESTED("deployment.requested", CUSTOMER, DEPLOYMENTS, "DEPLOY_REQUEST", ResourceType.DEPLOYMENT,
            FeatureFlags.CERTIFICATE_DEPLOYMENT, Allowed.NONE.attributes("targetType"),
            s -> "Started deploying " + certificate(s) + to(s.provider()),
            s -> "Could not start deploying " + certificate(s) + to(s.provider())),
    DEPLOYMENT_SUCCEEDED("deployment.succeeded", CUSTOMER, DEPLOYMENTS, "DEPLOY", ResourceType.DEPLOYMENT,
            FeatureFlags.CERTIFICATE_DEPLOYMENT, Allowed.NONE.attributes("targetType", "flow", "requestedBy"),
            s -> "Deployed " + certificate(s) + to(s.provider()),
            s -> "Deploying " + certificate(s) + to(s.provider()) + " failed"),
    // Written as a failure only (AuditEvents.failure); the success sentence is never stored.
    DEPLOYMENT_FAILED("deployment.failed", CUSTOMER, DEPLOYMENTS, "DEPLOY", ResourceType.DEPLOYMENT,
            FeatureFlags.CERTIFICATE_DEPLOYMENT, Allowed.NONE.attributes("targetType", "flow", "requestedBy"),
            s -> "Deploying " + certificate(s) + to(s.provider()) + " failed",
            s -> "Deploying " + certificate(s) + to(s.provider()) + " failed"),
    DEPLOYMENT_AUTO_STARTED("deployment.auto_started", CUSTOMER, DEPLOYMENTS, "AUTO_DEPLOY", ResourceType.DEPLOYMENT,
            FeatureFlags.CERTIFICATE_DEPLOYMENT, Allowed.NONE.attributes("targetType", "flow"),
            s -> "Started deploying " + certificate(s) + to(s.provider()) + " automatically",
            s -> "Could not start deploying " + certificate(s) + to(s.provider()) + " automatically"),
    // Written as a failure only, with the reason FEATURE_OFF: the automatic deploy did not happen.
    DEPLOYMENT_AUTO_SKIPPED("deployment.auto_skipped", CUSTOMER, DEPLOYMENTS, "AUTO_DEPLOY_SKIP",
            ResourceType.DEPLOYMENT, FeatureFlags.CERTIFICATE_DEPLOYMENT, Allowed.NONE.attributes("feature", "flow"),
            s -> "Skipped deploying " + certificate(s) + " automatically because " + featureOff(s),
            s -> "Skipped deploying " + certificate(s) + " automatically because " + featureOff(s)),

    // ── Credentials ──────────────────────────────────────────────────────
    // A credential's secret never reaches a row: what was supplied or changed (the credential details, the
    // secret store location, the scope configuration) is kept by field name only, by construction (nameOnly).
    // The name is the credential's description; the provider is in words (CredentialAuditRecorder).
    CREDENTIAL_CREATED("credential.created", CUSTOMER, CREDENTIALS, "CREATE", ResourceType.CREDENTIAL,
            FeatureFlags.CREDENTIALS_MANAGEMENT, Allowed.NONE.attributes("credentialType", "storedIn", "authMode")
                    .nameOnly(CredentialFields.KEPT_BY_NAME),
            s -> "Added the " + provider(s) + credentialKind(s) + "credential" + quoted(s.name()),
            s -> "Could not add the " + provider(s) + credentialKind(s) + "credential" + quoted(s.name())),
    CREDENTIAL_UPDATED("credential.updated", CUSTOMER, CREDENTIALS, "UPDATE", ResourceType.CREDENTIAL,
            FeatureFlags.CREDENTIALS_MANAGEMENT,
            Allowed.NONE.attributes("credentialType", "authMode").changes("name", "clientId")
                    .nameOnly(CredentialFields.KEPT_BY_NAME),
            s -> "Changed the " + provider(s) + credentialKind(s) + "credential" + quoted(s.name()),
            s -> "Could not change the " + provider(s) + credentialKind(s) + "credential" + quoted(s.name())),
    CREDENTIAL_DELETED("credential.deleted", CUSTOMER, CREDENTIALS, "DELETE", ResourceType.CREDENTIAL,
            FeatureFlags.CREDENTIALS_MANAGEMENT, Allowed.NONE.attributes("credentialType", "configurationsCleared"),
            s -> "Deleted the " + provider(s) + credentialKind(s) + "credential" + quoted(s.name()),
            s -> "Could not delete the " + provider(s) + credentialKind(s) + "credential" + quoted(s.name())),
    // A certificate's domain was given the DNS credential it is validated with (PATCH .../credential-config/dns).
    // The domain is the one validated; the credential before and after are their references (opaque ids).
    DNS_CREDENTIAL_ASSIGNED("dns_credential.assigned", CUSTOMER, CREDENTIALS, "ASSIGN", ResourceType.CREDENTIAL,
            FeatureFlags.CREDENTIALS_MANAGEMENT, Allowed.NONE.attributes("certificateDomain").changes("credential"),
            s -> "Assigned the " + provider(s) + "DNS credential" + quoted(s.name()) + to(s.domain()),
            s -> "Could not assign the " + provider(s) + "DNS credential" + quoted(s.name()) + to(s.domain())),

    // ── Deployments: where a certificate is deployed to ──────────────────
    // A deployment target is a deployment credential attached to a certificate's domain. Its per-certificate
    // plan (listener ARNs, gateway and namespace names) names the customer's cloud resources: kept by name only.
    DEPLOYMENT_TARGET_ADDED("deployment_target.added", CUSTOMER, DEPLOYMENTS, "CREATE", ResourceType.DEPLOYMENT,
            FeatureFlags.CERTIFICATE_DEPLOYMENT, Allowed.NONE.nameOnly("targets"),
            s -> "Added the " + provider(s) + "deployment target" + quoted(s.name()) + forDomain(s.domain()),
            s -> "Could not add the " + provider(s) + "deployment target" + quoted(s.name()) + forDomain(s.domain())),
    DEPLOYMENT_TARGET_UPDATED("deployment_target.updated", CUSTOMER, DEPLOYMENTS, "UPDATE", ResourceType.DEPLOYMENT,
            FeatureFlags.CERTIFICATE_DEPLOYMENT, Allowed.NONE.nameOnly("targets"),
            s -> "Changed the " + provider(s) + "deployment target" + quoted(s.name()) + forDomain(s.domain()),
            s -> "Could not change the " + provider(s) + "deployment target" + quoted(s.name())
                    + forDomain(s.domain())),
    DEPLOYMENT_TARGET_REMOVED("deployment_target.removed", CUSTOMER, DEPLOYMENTS, "DELETE", ResourceType.DEPLOYMENT,
            FeatureFlags.CERTIFICATE_DEPLOYMENT, Allowed.NONE,
            s -> "Removed the " + provider(s) + "deployment target" + quoted(s.name()) + from(s.domain()),
            s -> "Could not remove the " + provider(s) + "deployment target" + quoted(s.name()) + from(s.domain())),

    // ── Integrations and incidents ──────────────────────────────────────────
    INTEGRATION_CREATED("integration.created", CUSTOMER, INTEGRATIONS, "CREATE", ResourceType.INTEGRATION, null,
            Allowed.NONE.attributes("status"),
            s -> "Added the " + provider(s) + "integration",
            s -> "Could not add the " + provider(s) + "integration"),
    INTEGRATION_UPDATED("integration.updated", CUSTOMER, INTEGRATIONS, "UPDATE", ResourceType.INTEGRATION, null,
            Allowed.NONE.attributes("status"),
            s -> "Changed the " + provider(s) + "integration",
            s -> "Could not change the " + provider(s) + "integration"),
    INTEGRATION_DELETED("integration.deleted", CUSTOMER, INTEGRATIONS, "DELETE", ResourceType.INTEGRATION, null,
            Allowed.NONE.attributes("status"),
            s -> "Removed the " + provider(s) + "integration",
            s -> "Could not remove the " + provider(s) + "integration"),
    INCIDENT_TRIGGERED("incident.triggered", CUSTOMER, SUPPORT, "TRIGGER", ResourceType.INCIDENT, null,
            Allowed.NONE.attributes("source", "incidentReference"),
            s -> "Raised an incident" + in(s.provider()),
            s -> "Could not raise an incident" + in(s.provider())),
    // CertPing could not post a certificate, domain or IoT event to the organization's chat integration (Slack,
    // Teams). Written as a failure only, throttled (SupportAuditRecorder): a delivered notification is in the
    // integration's delivery history, not the trail. The message is never stored; the attribute is the event's code.
    INTEGRATION_NOTIFIED("integration.notified", CUSTOMER, INTEGRATIONS, "NOTIFY", ResourceType.INTEGRATION, null,
            Allowed.NONE.attributes("notification"),
            s -> "Sent a notification to " + integrationName(s),
            s -> "Could not send a notification to " + integrationName(s)),

    // ── Discovery ────────────────────────────────────────────────────────
    // A scan of the customer's cloud for certificates, run by the agent with a deployment credential. The scan's
    // own request id is the reference, so a scan's start and its outcome are found together; the provider is the
    // target in words ("Kubernetes", "AWS Certificate Manager") and the name is the credential's description.
    // The outcome rows are CertPing's (AuditScope.system), from the agent's results.
    DISCOVERY_SCAN_STARTED("discovery.scan_started", CUSTOMER, DISCOVERY, "SCAN_START", ResourceType.DISCOVERY,
            FeatureFlags.DISCOVERY, Allowed.NONE.attributes("targetType", "trigger"),
            s -> "Started a certificate discovery scan" + of(s.provider()) + withCredential(s.name()),
            s -> "Could not start a certificate discovery scan" + of(s.provider()) + withCredential(s.name())),
    DISCOVERY_SCAN_COMPLETED("discovery.scan_completed", CUSTOMER, DISCOVERY, "SCAN_COMPLETE",
            ResourceType.DISCOVERY, FeatureFlags.DISCOVERY, Allowed.NONE.attributes("targetType"),
            s -> "Finished a certificate discovery scan" + of(s.provider()) + found(s),
            s -> "The certificate discovery scan" + of(s.provider()) + " could not finish"),
    // Written as a failure only (AuditEvents.failure), with the agent's code or why CertPing gave the scan up.
    DISCOVERY_SCAN_FAILED("discovery.scan_failed", CUSTOMER, DISCOVERY, "SCAN_COMPLETE", ResourceType.DISCOVERY,
            FeatureFlags.DISCOVERY, Allowed.NONE.attributes("targetType"),
            s -> "The certificate discovery scan" + of(s.provider()) + " failed",
            s -> "The certificate discovery scan" + of(s.provider()) + " failed"),
    DISCOVERY_CONFIG_DELETED("discovery.config_deleted", CUSTOMER, DISCOVERY, "DELETE", ResourceType.DISCOVERY,
            FeatureFlags.DISCOVERY, Allowed.NONE.attributes("targetType"),
            s -> "Deleted the discovery configuration" + forTarget(s.provider()) + withCredential(s.name()),
            s -> "Could not delete the discovery configuration" + forTarget(s.provider()) + withCredential(s.name())),
    // A scan still running when its results arrived after certificate discovery was turned off. Turning the
    // feature off with scans running is recorded as feature.records_cleared or feature.paused, not here.
    DISCOVERY_SCANS_CANCELLED("discovery.scans_cancelled", CUSTOMER, DISCOVERY, "SCAN_CANCEL", ResourceType.DISCOVERY,
            FeatureFlags.DISCOVERY, Allowed.NONE.attributes("targetType", "cause"),
            s -> "Stopped " + scans(s) + of(s.provider()) + " because certificate discovery is turned off",
            s -> "Could not stop " + scans(s) + of(s.provider())),


    // ── Monitoring and alerts ────────────────────────────────────────────
    // An alert marked read or unread: the alert's state is the "state" attribute (READ or UNREAD).
    ALERT_UPDATED("alert.updated", CUSTOMER, MONITORING, "UPDATE", ResourceType.ALERT, FeatureFlags.ALERTS,
            Allowed.NONE.attributes("state", "alertType"),
            s -> "Marked the alert" + forDomain(s.domain()) + alertState(s),
            s -> "Could not mark the alert" + forDomain(s.domain()) + alertState(s)),


    // ── Machine identity (IoT) ───────────────────────────────────────────
    // Devices, the device sources (MDM and IoT platforms) they are synced from, their certificates and the
    // certificate profiles pushed to a source. A device is named by its name, a source by its display name and
    // provider in words, a certificate by its common name; the xref is the reference. An operator's free-text
    // note is never part of a row.
    IOT_DEVICE_DECOMMISSIONED("iot_device.decommissioned", CUSTOMER, MACHINE_IDENTITY, "DECOMMISSION",
            ResourceType.IOT_DEVICE, FeatureFlags.IOT_DEVICE_MANAGEMENT, Allowed.NONE.changes("status"),
            s -> "Decommissioned the device" + quoted(s.name()),
            s -> "Could not decommission the device" + quoted(s.name())),
    IOT_DEVICE_ARCHIVED("iot_device.archived", CUSTOMER, MACHINE_IDENTITY, "ARCHIVE", ResourceType.IOT_DEVICE,
            FeatureFlags.IOT_DEVICE_MANAGEMENT, Allowed.NONE,
            s -> "Archived the device" + quoted(s.name()),
            s -> "Could not archive the device" + quoted(s.name())),
    IOT_DEVICE_RESTORED("iot_device.restored", CUSTOMER, MACHINE_IDENTITY, "RESTORE", ResourceType.IOT_DEVICE,
            FeatureFlags.IOT_DEVICE_MANAGEMENT, Allowed.NONE,
            s -> "Restored the device" + quoted(s.name()) + " to the inventory",
            s -> "Could not restore the device" + quoted(s.name()) + " to the inventory"),
    IOT_SOURCE_SYNC_STARTED("iot_source.sync_started", CUSTOMER, MACHINE_IDENTITY, "SYNC_START",
            ResourceType.IOT_SOURCE, FeatureFlags.IOT_DEVICE_MANAGEMENT, Allowed.NONE.attributes("syncRef"),
            s -> "Started a device sync from the " + provider(s) + "source" + quoted(s.name()),
            s -> "Could not start a device sync from the " + provider(s) + "source" + quoted(s.name())),
    IOT_SOURCE_SYNC_STOPPED("iot_source.sync_stopped", CUSTOMER, MACHINE_IDENTITY, "SYNC_STOP",
            ResourceType.IOT_SOURCE, FeatureFlags.IOT_DEVICE_MANAGEMENT, Allowed.NONE,
            s -> "Stopped the scheduled device sync from the " + provider(s) + "source" + quoted(s.name()),
            s -> "Could not stop the scheduled device sync from the " + provider(s) + "source" + quoted(s.name())),
    // The member's request: the certificate authority revokes it once the operation is dispatched.
    IOT_CERTIFICATE_REVOKED("iot_certificate.revoked", CUSTOMER, MACHINE_IDENTITY, "REVOKE",
            ResourceType.IOT_CERTIFICATE, FeatureFlags.IOT_DEVICE_MANAGEMENT,
            Allowed.NONE.attributes("reason", "caProvider", "operationRef"),
            s -> "Requested the revocation of the device certificate" + quoted(s.name()),
            s -> "Could not revoke the device certificate" + quoted(s.name())),
    IOT_PROFILE_CREATED("iot_profile.created", CUSTOMER, MACHINE_IDENTITY, "CREATE", ResourceType.IOT_PROFILE,
            FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT,
            Allowed.NONE.attributes("lifecycleStatus", "targetPlatform", "sourceRef"),
            s -> "Created the certificate profile" + quoted(s.name()),
            s -> "Could not create the certificate profile" + quoted(s.name())),
    // The settings changed are named in "changed"; their values (validity, subject, key options) are not kept.
    IOT_PROFILE_UPDATED("iot_profile.updated", CUSTOMER, MACHINE_IDENTITY, "UPDATE", ResourceType.IOT_PROFILE,
            FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT,
            Allowed.NONE.attributes("changed", "sentToProvider").changes("lifecycleStatus"),
            s -> "Changed the certificate profile" + quoted(s.name()),
            s -> "Could not change the certificate profile" + quoted(s.name())),
    // A profile its source no longer has, removed from the list; its certificates' history is kept.
    IOT_PROFILE_DELETED("iot_profile.deleted", CUSTOMER, MACHINE_IDENTITY, "DELETE", ResourceType.IOT_PROFILE,
            FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT, Allowed.NONE,
            s -> "Deleted the certificate profile" + quoted(s.name()),
            s -> "Could not delete the certificate profile" + quoted(s.name())),
    // Written as a failure only, by CertPing on the agent's SCEP_CERT_RESULT: a device's enrollment through a source
    // ended without a certificate (challenge rejected, CA refused, Intune or the CA unreachable). The reason is the
    // agent's code; its detail text can echo the CSR subject and stays in the enrollment's event row.
    IOT_ENROLLMENT_FAILED("iot_certificate.enrollment_failed", CUSTOMER, MACHINE_IDENTITY, "ENROLL",
            ResourceType.IOT_SOURCE, FeatureFlags.IOT_DEVICE_MANAGEMENT,
            Allowed.NONE.attributes("stage", "enrollmentRef", "retryable"),
            s -> "Enrolled a device certificate through the " + provider(s) + "source" + quoted(s.name()),
            s -> "A device certificate enrollment through the " + provider(s) + "source" + quoted(s.name())
                    + " ended without a certificate"),


    // ── Agent health ─────────────────────────────────────────────────────
    // The CertPing agent's health reporting, filed with monitoring: how often it reports, and deep checks of
    // what it can reach. A deep check names no secret or vault path, only its id as the reference.
    AGENT_HEALTH_CADENCE_CHANGED("agent_health.cadence_changed", CUSTOMER, MONITORING, "UPDATE", ResourceType.AGENT,
            FeatureFlags.AGENT_HEALTH_MONITORING, Allowed.NONE.changes("heartbeatCadenceMinutes"),
            s -> "Changed how often the agent reports its health" + cadence(s),
            s -> "Could not change how often the agent reports its health"),
    AGENT_HEALTH_DEEP_CHECK_REQUESTED("agent_health.deep_check_requested", CUSTOMER, MONITORING, "DEEP_CHECK",
            ResourceType.AGENT, FeatureFlags.AGENT_HEALTH_MONITORING, Allowed.NONE,
            s -> "Started a deep health check of the agent",
            s -> "Could not start a deep health check of the agent"),

    // ── Agent tokens ─────────────────────────────────────────────────────
    // The bearer tokens agents connect with, filed with access control (a token is access to the organization's
    // jobs). The row names the token (its id and name), never its value.
    AGENT_TOKEN_CREATED("agent_token.created", CUSTOMER, ACCESS_CONTROL, "CREATE", ResourceType.AGENT, null,
            Allowed.NONE.attributes("expiresAt"),
            s -> "Created the agent token" + quoted(s.name()),
            s -> "Could not create an agent token"),
    AGENT_TOKEN_REVOKED("agent_token.revoked", CUSTOMER, ACCESS_CONTROL, "REVOKE", ResourceType.AGENT, null,
            Allowed.NONE,
            s -> "Revoked the agent token" + quoted(s.name()),
            s -> "Could not revoke the agent token"),


    // ── Sensitive access (the Access view) ───────────────────────────────
    // Reads of something sensitive, recorded with @AuditedRead and grouped to one row per organization, actor,
    // event and target every 15 minutes (AuditedReads). Nothing read is ever part of the row: it says what was
    // read, never its content.
    ACCESS_AGENT_CONNECTION_VIEWED("access.agent_connection_viewed", CUSTOMER, ACCESS, "VIEW_SECRET",
            ResourceType.AGENT, null, Allowed.NONE,
            s -> "Viewed the agent's connection string",
            s -> "Could not view the agent's connection string"),
    ACCESS_CBOM_DOWNLOADED("access.cbom_downloaded", CUSTOMER, ACCESS, "DOWNLOAD", ResourceType.CERTIFICATE,
            FeatureFlags.PQC_READINESS, Allowed.NONE,
            s -> "Downloaded the cryptographic bill of materials (CBOM)",
            s -> "Could not download the cryptographic bill of materials (CBOM)"),
    ACCESS_AUDIT_LOG_VIEWED("access.audit_log_viewed", CUSTOMER, ACCESS, "VIEW", ResourceType.AUDIT, null,
            Allowed.NONE,
            s -> "Viewed the audit log",
            s -> "Could not view the audit log"),
    // A certificate download refused before any certificate was resolved (not found in the caller's organization,
    // a private-key format they may not download, rate limited, the limiter unavailable): an attempt to read key
    // material, not a certificate's event. Written as a failure only, durably, by CertExportAuditRecorder; a
    // refusal of a resolved certificate is that certificate's certificate.exported failure. The reference is the
    // xref the caller sent, if any.
    ACCESS_CERTIFICATE_EXPORT_REFUSED("access.certificate_export_refused", CUSTOMER, ACCESS, "EXPORT",
            ResourceType.CERTIFICATE, null, Allowed.NONE.attributes("keyIncluded"),
            s -> "Tried to download a certificate" + as(s.format()),
            s -> "Could not download a certificate" + as(s.format())),

    // ── Internal: platform administration ────────────────────────────────
    // What a super admin did to the platform itself or to an organization's plumbing: it belongs to no
    // customer's trail. The organization acted on, when there is one, is the row's organization.
    ADMIN_ORGANIZATION_PROVISIONED("admin.organization_provisioned", INTERNAL, PLATFORM, "PROVISION",
            ResourceType.ORGANIZATION, null, Allowed.NONE.attributes("status"),
            s -> "Provisioned the organization's agent queue",
            s -> "Could not provision the organization's agent queue"),
    ADMIN_AGENT_SAS_ROTATED("admin.agent_sas_rotated", INTERNAL, PLATFORM, "ROTATE_SECRET", ResourceType.AGENT, null,
            Allowed.NONE.attributes("status"),
            s -> "Rotated the organization's agent connection secret",
            s -> "Could not rotate the organization's agent connection secret"),

    // ── Internal: requests ───────────────────────────────────────────────
    // One row per mutating request (POST, PUT, PATCH, DELETE): the route pattern, never the raw path,
    // query or the caller's email. Page loads (GET) are not audit events.
    API_REQUEST("api.request", INTERNAL, PLATFORM, "API_REQUEST", ResourceType.API, null,
            Allowed.NONE.attributes("method", "route", "status", "durationMs"),
            s -> request(s) + returned(s),
            s -> request(s) + returned(s)),

    // ── Internal: platform settings ──────────────────────────────────────
    // A platform-wide setting a super admin changed (global_settings): it belongs to no customer's trail.
    PLATFORM_SETTING_CHANGED("platform_setting.changed", INTERNAL, PLATFORM, "PLATFORM_SETTING_CHANGE",
            ResourceType.ADMIN, null, Allowed.NONE.changes("value"),
            s -> "Changed the platform setting" + quoted(s.name()),
            s -> "Could not change the platform setting" + quoted(s.name())),
    // How long audit events are kept (global_settings.audit_retention_months, 6 to 36). The super admin's
    // reason is internal-only; effectiveFrom is the first retention run that applies the new period.
    AUDIT_RETENTION_CHANGED("audit.retention_changed", INTERNAL, PLATFORM, "AUDIT_RETENTION_CHANGE",
            ResourceType.AUDIT, null, Allowed.NONE.changes("months").attributes("effectiveFrom")
                    .internalOnly("reason"),
            s -> "Changed how long audit events are kept" + months(s.count()),
            s -> "Could not change how long audit events are kept"),

    // ── Internal: the audit trail's own upkeep ───────────────────────────
    AUDIT_PARTITION_CREATED("audit.partition_created", INTERNAL, PLATFORM, "AUDIT_PARTITION_CREATE",
            ResourceType.AUDIT, null, Allowed.NONE.attributes("sqlState"),
            s -> "Created the audit partition" + named(s.name()),
            s -> "Could not create the audit partition" + named(s.name())),
    // Every save of the retention period, changed or not: nothing is dropped before the first. The super admin's
    // reason is internal-only.
    AUDIT_RETENTION_CONFIRMED("audit.retention_confirmed", INTERNAL, PLATFORM, "AUDIT_RETENTION_CONFIRM",
            ResourceType.AUDIT, null, Allowed.NONE.attributes("effectiveFrom", "firstConfirmation")
                    .internalOnly("reason"),
            s -> "Confirmed that audit events are kept" + forMonths(s.count()),
            s -> "Could not confirm how long audit events are kept"),
    // One row per month the retention job dropped, written once its transaction committed; a month that could not
    // be dropped is a failure row with its name, a run that failed before dropping one without.
    AUDIT_PARTITION_DROPPED("audit.partition_dropped", INTERNAL, PLATFORM, "AUDIT_PARTITION_DROP",
            ResourceType.AUDIT, null, Allowed.NONE.attributes("cutoff", "retentionMonths", "estimatedRows", "sqlState"),
            s -> "Dropped the expired audit partition" + named(s.name()),
            s -> s.name() == null || s.name().isBlank()
                    ? "Could not drop the expired audit partitions" + before(s.attributes().get("cutoff"))
                    : "Could not drop the expired audit partition " + s.name()),
    AUDIT_DEFAULT_PARTITION_NOT_EMPTY("audit.default_partition_not_empty", INTERNAL, PLATFORM,
            "AUDIT_PARTITION_CHECK", ResourceType.AUDIT, null, Allowed.NONE,
            s -> "The default audit partition holds " + rows(s) + "; create the missing months and move them",
            s -> "The default audit partition holds " + rows(s) + "; create the missing months and move them");

    /** What a member-targeted summary is stored with in place of the member's name. */
    public static final String STORED_MEMBER = "a member";

    private static final Map<String, AuditEventType> BY_KEY = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(AuditEventType::key, Function.identity()));

    private final String key;
    private final AuditVisibility visibility;
    private final AuditCategory category;
    private final String action;
    private final ResourceType resourceType;
    private final String featureKey;
    private final Allowed allowed;
    private final Function<AuditSubject, String> summary;
    private final Function<AuditSubject, String> failure;

    AuditEventType(String key, AuditVisibility visibility, AuditCategory category, String action,
                   ResourceType resourceType, String featureKey, Allowed allowed,
                   Function<AuditSubject, String> summary, Function<AuditSubject, String> failure) {
        this.key = key;
        this.visibility = visibility;
        this.category = category;
        this.action = action;
        this.resourceType = resourceType;
        this.featureKey = featureKey;
        this.allowed = allowed;
        this.summary = summary;
        this.failure = failure;
    }

    /** The entry stored under {@code key}, or empty for a key this build does not know. */
    public static Optional<AuditEventType> byKey(String key) {
        return Optional.ofNullable(key).map(BY_KEY::get);
    }

    public String key() { return key; }

    public AuditVisibility visibility() { return visibility; }

    public AuditCategory category() { return category; }

    /** The stable action code a row is filtered by; several events may share one. */
    public String action() { return action; }

    public ResourceType resourceType() { return resourceType; }

    /** The {@link FeatureFlags} key the event belongs to, or {@code null} for a core event. */
    public String featureKey() { return featureKey; }

    public boolean isCore() { return featureKey == null; }

    public AuditSensitivity sensitivity() {
        return category == AuditCategory.ACCESS ? AuditSensitivity.SENSITIVE_READ : CHANGE;
    }

    /** The attribute names a row of this event may carry; any other is dropped when the row is built. */
    public Set<String> allowedAttributes() { return allowed.attributes(); }

    /** The changed field names a row may carry with their values; any other is dropped when the row is built. */
    public Set<String> allowedChanges() { return allowed.changes(); }

    /**
     * Personal fields of a member (email, name): a change to one is kept as the field name alone, with
     * no before or after, so the row says what changed without storing personal data.
     */
    public Set<String> personalChanges() { return allowed.personal(); }

    /**
     * Secret fields (a client secret, a key): a change to one, or an attribute of one, is kept as the
     * name alone, never a value, not even a redacted one. The row says the secret changed by
     * construction, rather than by the sanitizer catching it.
     */
    public Set<String> nameOnly() { return allowed.nameOnly(); }

    /**
     * Attributes kept on internal rows only, e.g. an operator's free-text reason: a customer row of the event
     * drops them, so the platform's notes never reach a customer's trail whatever the caller passes.
     */
    public Set<String> internalOnlyAttributes() { return allowed.internalOnly(); }

    /**
     * What a row of an event may carry in its details: attribute names, changed fields kept with their
     * values, changed personal fields kept by name only, secret fields (changes or attributes) kept
     * by name only, and attributes only its internal rows keep.
     */
    public record Allowed(Set<String> attributes, Set<String> changes, Set<String> personal, Set<String> nameOnly,
                          Set<String> internalOnly) {

        public static final Allowed NONE = new Allowed(Set.of(), Set.of(), Set.of(), Set.of(), Set.of());

        Allowed attributes(String... names) {
            return new Allowed(Set.of(names), changes, personal, nameOnly, internalOnly);
        }

        Allowed changes(String... names) {
            return new Allowed(attributes, Set.of(names), personal, nameOnly, internalOnly);
        }

        Allowed personal(String... names) {
            return new Allowed(attributes, changes, Set.of(names), nameOnly, internalOnly);
        }

        Allowed nameOnly(String... names) {
            return nameOnly(Set.of(names));
        }

        Allowed nameOnly(Set<String> names) {
            return new Allowed(attributes, changes, personal, Set.copyOf(names), internalOnly);
        }

        /** Attributes allowed on internal rows of the event only; dropped from its customer rows. */
        Allowed internalOnly(String... names) {
            return new Allowed(attributes, changes, personal, nameOnly, Set.of(names));
        }
    }

    /** Whether the target is a member, whose name is rendered from the live users row when read. */
    public boolean rendersTargetWhenRead() {
        return resourceType == ResourceType.USER;
    }

    /** The sentence for the event having happened. */
    public String summary(AuditSubject subject) {
        return summary.apply(subject == null ? AuditSubject.NONE : subject);
    }

    /** The sentence for the event having been attempted and failed. */
    public String failure(AuditSubject subject) {
        return failure.apply(subject == null ? AuditSubject.NONE : subject);
    }

    private static String member(AuditSubject s) {
        return s.name() == null || s.name().isBlank() ? STORED_MEMBER : s.name();
    }

    private static String provider(AuditSubject s) {
        return s.provider() == null || s.provider().isBlank() ? "" : s.provider() + " ";
    }

    private static String quoted(String name) {
        return name == null || name.isBlank() ? "" : " '" + name + "'";
    }

    /** " to 12 months", or nothing. */
    private static String months(Integer months) {
        return months == null ? "" : " to " + months + (months == 1 ? " month" : " months");
    }

    /** " for 12 months", or nothing. */
    private static String forMonths(Integer months) {
        return months == null ? "" : " for " + months + (months == 1 ? " month" : " months");
    }

    /** " before 2025-10-01T00:00:00Z", or nothing. */
    private static String before(String cutoff) {
        return cutoff == null || cutoff.isBlank() ? "" : " before " + cutoff;
    }

    private static String named(String name) {
        return name == null || name.isBlank() ? "" : " " + name;
    }

    /** " as PEM", or nothing. */
    private static String as(String format) {
        return format == null || format.isBlank() ? "" : " as " + format;
    }

    /** "the certificate for example.com", or "the certificate" when no domain (or name) is known. */
    private static String certificate(AuditSubject s) {
        String domain = s.domain() == null || s.domain().isBlank() ? s.name() : s.domain();
        return domain == null || domain.isBlank() ? "the certificate" : "the certificate for " + domain;
    }

    /** " for example.com", or nothing. */
    private static String forDomain(AuditSubject s) {
        String domain = s.domain() == null || s.domain().isBlank() ? s.name() : s.domain();
        return domain == null || domain.isBlank() ? "" : " for " + domain;
    }

    /** Why an automatic renewal was skipped: a CertPing DNS key it needs expired, or {@link #featureOffOrNotInPlan}. */
    private static String skipCause(AuditSubject s) {
        String dnsKeyExpiredOn = s.attributes().get("dnsKeyExpiredOn");
        return dnsKeyExpiredOn == null || dnsKeyExpiredOn.isBlank()
                ? featureOffOrNotInPlan(s)
                : "its CertPing DNS key expired on " + dnsKeyExpiredOn + " (UTC)";
    }

    /** Why an automatic renewal was skipped: its plan does not include the certificate's CA, or a feature is off. */
    private static String featureOffOrNotInPlan(AuditSubject s) {
        String plan = s.attributes().get("plan");
        String feature = s.attributes().get("feature");
        if (plan == null || plan.isBlank() || feature == null || feature.isBlank()) {
            return featureOff(s);
        }
        return "the " + plan + " plan does not include '" + feature + "'";
    }

    /**
     * "the feature 'Certificate Deployment' is off", "the features 'Certificate Renewal' and 'Let's Encrypt' are
     * off", or "a feature it needs is off"; from the {@code feature} attribute (feature names joined by ", ").
     */
    private static String featureOff(AuditSubject s) {
        String feature = s.attributes().get("feature");
        if (feature == null || feature.isBlank()) {
            return "a feature it needs is off";
        }
        String[] names = feature.split(", ");
        if (names.length == 1) {
            return "the feature '" + names[0] + "' is off";
        }
        StringBuilder text = new StringBuilder("the features ");
        for (int i = 0; i < names.length; i++) {
            text.append(i == 0 ? "" : i == names.length - 1 ? " and " : ", ").append('\'').append(names[i]).append('\'');
        }
        return text.append(" are off").toString();
    }

    private static String capitalised(String text) {
        return text.isEmpty() ? text : Character.toUpperCase(text.charAt(0)) + text.substring(1);
    }

    private static String in(String provider) {
        return provider == null || provider.isBlank() ? "" : " in " + provider;
    }

    /**
     * " with a password", " with single sign-on", " with Google", or nothing; from the {@code method}
     * attribute. A method this build has no words for reads as itself.
     */
    private static String signInMethod(AuditSubject s) {
        String method = s.attributes().get("method");
        if (method == null || method.isBlank()) {
            return "";
        }
        return switch (method) {
            case "PASSWORD" -> " with a password";
            case "OIDC" -> " with single sign-on";
            case "GOOGLE" -> " with Google";
            case "MICROSOFT" -> " with Microsoft";
            case "GITHUB" -> " with GitHub";
            case "LINKEDIN" -> " with LinkedIn";
            default -> " with " + method;
        };
    }

    /** "5 failed sign-ins", "1 failed sign-in", or "repeated failed sign-ins"; from the {@code attempts} attribute. */
    private static String failedSignIns(AuditSubject s) {
        String attempts = s.attributes().get("attempts");
        if (attempts == null || !attempts.matches("\\d{1,9}")) {
            return "repeated failed sign-ins";
        }
        return "1".equals(attempts) ? "1 failed sign-in" : attempts + " failed sign-ins";
    }

    /** "12 records", "1 record", or "the records" when the count is unknown. */
    private static String records(AuditSubject s) {
        if (s.count() == null) {
            return "the records";
        }
        return s.count() == 1 ? "1 record" : s.count() + " records";
    }

    /** "POST /api/v1/certs/{xref}", or "A request" when the method or route is unknown. */
    private static String request(AuditSubject s) {
        String method = s.attributes().get("method");
        String route = s.attributes().get("route");
        if (method == null || method.isBlank()) {
            return "A request";
        }
        return route == null || route.isBlank() ? method + " request" : method + " " + route;
    }

    private static String returned(AuditSubject s) {
        String status = s.attributes().get("status");
        return status == null || status.isBlank() ? "" : " returned " + status;
    }

    /** " more than 30 days ago", or nothing; from the {@code retentionDays} attribute. */
    private static String olderThan(AuditSubject s) {
        String days = s.attributes().get("retentionDays");
        if (days == null || days.isBlank()) {
            return "";
        }
        return " more than " + days.trim() + ("1".equals(days.trim()) ? " day ago" : " days ago");
    }

    /** "DNS ", "deployment ", or nothing; from the {@code credentialType} attribute. */
    private static String credentialKind(AuditSubject s) {
        String type = s.attributes().get("credentialType");
        if (type == null) {
            return "";
        }
        return switch (type) {
            case "DNS" -> "DNS ";
            case "DEPLOYMENT" -> "deployment ";
            default -> "";
        };
    }

    /** " to example.com" (or " to Azure Key Vault"), or nothing. */
    private static String to(String domain) {
        return domain == null || domain.isBlank() ? "" : " to " + domain;
    }

    /** " from example.com" (or " from Let's Encrypt"), or nothing. */
    private static String from(String domain) {
        return domain == null || domain.isBlank() ? "" : " from " + domain;
    }

    /** " for example.com", or nothing. */
    private static String forDomain(String domain) {
        return domain == null || domain.isBlank() ? "" : " for " + domain;
    }

    // ── Helpers: discovery, monitoring, IoT, agent health ────────────────

    /** " of Kubernetes", or nothing. */
    private static String of(String target) {
        return target == null || target.isBlank() ? "" : " of " + target;
    }

    /** " for Kubernetes", or nothing. */
    private static String forTarget(String target) {
        return target == null || target.isBlank() ? "" : " for " + target;
    }

    /** " with the credential 'Prod'", or nothing. */
    private static String withCredential(String name) {
        return name == null || name.isBlank() ? "" : " with the credential '" + name + "'";
    }

    /** " and found 12 certificates", " and found 1 certificate", or nothing when the count is unknown. */
    private static String found(AuditSubject s) {
        if (s.count() == null) {
            return "";
        }
        return " and found " + (s.count() == 1 ? "1 certificate" : s.count() + " certificates");
    }

    /** "1 discovery scan", "3 discovery scans", or "the discovery scans" when the count is unknown. */
    private static String scans(AuditSubject s) {
        if (s.count() == null) {
            return "the discovery scans";
        }
        return s.count() == 1 ? "1 discovery scan" : s.count() + " discovery scans";
    }

    /** " example.com", or " the monitor". */
    private static String orTheMonitor(String target) {
        return target == null || target.isBlank() ? " the monitor" : " " + target;
    }

    /** " as read", " as unread", or nothing; from the {@code state} attribute. */
    private static String alertState(AuditSubject s) {
        String state = s.attributes().get("state");
        if (state == null) {
            return "";
        }
        return switch (state) {
            case "READ" -> " as read";
            case "UNREAD" -> " as unread";
            default -> "";
        };
    }

    /** " to every 15 minutes", or nothing; the new heartbeat interval from the changes. */
    private static String cadence(AuditSubject s) {
        for (AuditChange change : s.changes()) {
            if ("heartbeatCadenceMinutes".equals(change.field()) && change.after() != null
                    && change.after().matches("\\d{1,6}")) {
                return "1".equals(change.after()) ? " to every minute" : " to every " + change.after() + " minutes";
            }
        }
        return "";
    }

    // ── Helpers: integrations ─────────────────────────────────────────────

    /** "Slack", "Microsoft Teams", or "an integration" when the provider is unknown. */
    private static String integrationName(AuditSubject s) {
        return s.provider() == null || s.provider().isBlank() ? "an integration" : s.provider();
    }

    /** "57 audit log entries" for {@code log} "audit log", or "the audit log" when the count is not known. */
    private static String entries(AuditSubject s, String log) {
        if (s.count() == null) {
            return "the " + log;
        }
        return s.count() == 1 ? "1 " + log + " entry" : s.count() + " " + log + " entries";
    }

    private static String rows(AuditSubject s) {
        int n = s.count() == null ? 0 : s.count();
        return n == 1 ? "1 row" : n + " rows";
    }
}
