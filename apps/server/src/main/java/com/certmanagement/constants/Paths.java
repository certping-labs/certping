// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.constants;

public final class Paths {
	private Paths() {
	}

	// AlertController
	public static final String ALERTS = "/api/v1/alerts";
	public static final String ALERTS_ID = "/api/v1/alerts/{id}";

	// AuditController - unified collection endpoint with query-param filters
	public static final String AUDIT_LOGS = "/api/v1/audit-logs";
	public static final String AUDIT_LOGS_RESOURCES = "/api/v1/audit-logs/resources";
	public static final String AUDIT_LOGS_ACTIONS = "/api/v1/audit-logs/actions";
	public static final String AUDIT_LOGS_CATEGORIES = "/api/v1/audit-logs/categories";
	public static final String AUDIT_LOGS_EXPORT = "/api/v1/audit-logs/export";
	public static final String AUDIT_LOGS_ACCESS = "/api/v1/audit-logs/access";
	public static final String AUDIT_LOGS_ACCESS_EXPORT = "/api/v1/audit-logs/access/export";
	public static final String AUDIT_LOGS_ACCESS_ACTIVITIES = "/api/v1/audit-logs/access/activities";
	// AdminAuditController — the platform view of the audit trail (super admins)
	public static final String ADMIN_AUDIT_LOGS = "/api/v1/admin/audit-logs";
	public static final String ADMIN_AUDIT_LOGS_EXPORT = "/api/v1/admin/audit-logs/export";
	public static final String ADMIN_AUDIT_LOGS_ACTIONS = "/api/v1/admin/audit-logs/actions";
	public static final String ADMIN_AUDIT_LOGS_RESOURCES = "/api/v1/admin/audit-logs/resources";
	public static final String ADMIN_AUDIT_LOGS_CATEGORIES = "/api/v1/admin/audit-logs/categories";

	// AuthController
	public static final String AUTH_BASE = "/api/auth";

	public static final String AUTH_REFRESH = "/api/auth/refresh";
	public static final String AUTH_VALIDATE = "/api/auth/validate";
	public static final String AUTH_ME = "/api/auth/me";
	public static final String AUTH_LOGOUT = "/api/auth/logout";

	// Local accounts: sign-in, first-run setup, password reset and change
	public static final String AUTH_LOGIN                 = "/api/auth/login";
	public static final String AUTH_SETUP_STATUS          = "/api/auth/setup/status";
	public static final String AUTH_SETUP                 = "/api/auth/setup";
	public static final String AUTH_FORGOT_PASSWORD       = "/api/auth/forgot-password";
	public static final String AUTH_RESET_PASSWORD        = "/api/auth/reset-password/{token}";
	public static final String AUTH_CHANGE_PASSWORD       = "/api/auth/change-password";
	public static final String AUTH_LOGIN_MFA             = "/api/auth/login/mfa";
	public static final String AUTH_MFA                   = "/api/auth/mfa";
	public static final String AUTH_MFA_ENROLL            = "/api/auth/mfa/enroll";
	public static final String AUTH_MFA_CONFIRM           = "/api/auth/mfa/confirm";

	// NotificationController
	public static final String NOTIFICATIONS_BASE = "/api/notifications";

	// OrganizationController
	public static final String ORGANIZATIONS_BASE = "/api/v1/organizations";
	public static final String ORGANIZATIONS_ID = "/api/v1/organizations/{id}";
	public static final String ORGANIZATIONS_NAME = "/api/v1/organizations/name/{name}";
	public static final String ORGANIZATIONS_DOMAIN = "/api/v1/organizations/domain/{domain}";
	public static final String ORGANIZATIONS_SLUG = "/api/v1/organizations/slug/{slug}";

	// UserController
	public static final String USERS_BASE = "/api/v1/users";
	public static final String USERS_ID = "/api/v1/users/{id}";
	public static final String USERS_DISABLE = "/api/v1/users/{id}/disable";
	public static final String USERS_ORGANIZATION_BASE = "/api/v1/users/organization";
	public static final String USERS_ORGANIZATION_ID = "/api/v1/users/organization/{id}";
	public static final String USERS_ORGANIZATION_DISABLE = "/api/v1/users/organization/{id}/disable";

	// CertManagementController — cert lifecycle per organization
	public static final String CERTS_BASE = "/api/v1/certs";
	public static final String CERTS_HISTORY = "/api/v1/certs/history";
	public static final String CERTS_ISSUE = "/api/v1/certs/issue";
	public static final String CERTS_CA_PROVIDERS = "/api/v1/certs/ca-providers";
	public static final String CERTS_DASHBOARD = "/api/v1/certs/dashboard";
	public static final String CERTS_EXPIRING = "/api/v1/certs/expiring";
	public static final String CERTS_VALUE_SUMMARY = "/api/v1/certs/value-summary";
	// DomainCredentialConfigController: a certificate domain's DNS credential and deployment targets
	public static final String CERT_DOMAIN_CREDENTIAL_CONFIG = "/api/v1/certs/domains/{domain}/credential-config";

	public static final String CERTS_GET = "/api/v1/certs/{certXref}";
	public static final String USER_DOMAIN_CERTS_ID = "/api/v1/user-domain-certificates/{userDomainCertId}";
	public static final String CERTS_CONVERT_TO_AUTOMATED = "/api/v1/certs/{certXref}/convert-to-automated";
	public static final String CERTS_RENEW = "/api/v1/certs/{certXref}/renew";
	public static final String CERTS_DEPLOY = "/api/v1/certs/{certXref}/deploy";
	public static final String CERTS_REVOKE = "/api/v1/certs/{certXref}/revoke";
	public static final String CERTS_EXPORT = "/api/v1/certs/{certXref}/export";
	public static final String DEPLOYMENTS_BASE = "/api/v1/deployments";
	public static final String DEPLOYMENTS_UDC_SUMMARY = "/api/v1/deployments/user-domain-certs/summary";
	public static final String DEPLOYMENTS_CRED_CONFIG = "/api/v1/deployments/cred-config";

	// Manual issuance endpoints
	public static final String CERT_ISSUE_MANUAL = "/api/v1/certs/issue-manual";
	public static final String CERT_TXT_RECORDS = "/api/v1/certs/{certXref}/txt-records";
	public static final String CERT_VALIDATE_DNS = "/api/v1/certs/{certXref}/validate-dns";

	// Discovery endpoints
	public static final String DISCOVERY_TRIGGER = "/api/v1/discovery/trigger";
	public static final String DISCOVERY_TRIGGER_ALL = "/api/v1/discovery/trigger/all";
	public static final String DISCOVERY_TRIGGER_CONFIG = "/api/v1/discovery/trigger/{configId}";
	public static final String DISCOVERY_CERTS = "/api/v1/discovery/certs";
	public static final String DISCOVERY_CERT = "/api/v1/discovery/certs/{id}";

	// CBOM endpoint
	public static final String CBOM_DOWNLOAD = "/api/v1/cbom";

	// PQC readiness endpoint
	public static final String PQC_READINESS = "/api/v1/pqc-readiness";
	public static final String PQC_READINESS_CERTIFICATES = "/api/v1/pqc-readiness/certificates";

	// CertCredentialController — credential references of the caller's organization
	public static final String CERT_CREDS_BASE = "/api/v1/credentials";
	public static final String CERT_CREDS_DNS = "/api/v1/credentials/dns";
	public static final String CERT_CREDS_DEPLOYMENT = "/api/v1/credentials/deployment";
	public static final String CERT_CREDS_CA = "/api/v1/credentials/ca";
	public static final String CERT_CREDS_CA_XREF = "/api/v1/credentials/ca/{credXref}";
	public static final String CERTIFICATE_AUTHORITIES = "/api/v1/certificate-authorities";
	public static final String CERT_CREDS_DISCOVERY = "/api/v1/credentials/discovery";
	public static final String CERT_CREDS_XREF = "/api/v1/credentials/{credXref}";

	// AgentHealthController
	public static final String AGENT_HEALTH = "/api/v1/agent/health";
	public static final String AGENT_HEALTH_CADENCE = "/api/v1/agent/health/cadence";
	public static final String AGENT_DEEP_HEALTH_CHECKS = "/api/v1/agent/health/deep-checks";
	public static final String AGENT_DEEP_HEALTH_CHECK = "/api/v1/agent/health/deep-checks/{deepCheckId}";
	public static final String AGENT_DEEP_HEALTH_CHECK_METRICS = "/api/v1/agent/health/deep-checks/{deepCheckId}/metrics";

	// AdminController (system bootstrap + local auth)
	public static final String ADMIN_BASE = "/api/v1/admin";
	public static final String ADMIN_LOGIN = "/api/v1/admin/login";
	public static final String ADMIN_STATUS = "/api/v1/admin/status";
	public static final String ADMIN_USERS = "/api/v1/admin/users";
	/** The signed-in platform super admin's working organization. */
	public static final String ADMIN_ME_ORGANIZATION = "/api/v1/admin/me/organization";
	public static final String ADMIN_CHANGE_PW = "/api/v1/admin/change-password";

	// RoleController (roles & permissions management)
	public static final String ROLES_BASE = "/api/v1/roles";
	public static final String ROLES_ID = "/api/v1/roles/{id}";
	public static final String ROLES_PERMISSIONS = "/api/v1/roles/{id}/permissions";
	public static final String PERMISSIONS_BASE = "/api/v1/permissions";
	public static final String PERMISSIONS_BY_RESOURCE = "/api/v1/permissions/resource/{resource}";

	// User-level permission management (in RoleController)
	public static final String USERS_ROLES = "/api/v1/users/{id}/roles";
	public static final String USERS_PERMISSIONS = "/api/v1/users/{id}/permissions";

	// FeatureFlagController (org-scoped)
	public static final String FEATURE_FLAGS = "/api/v1/feature-flags";
	public static final String FEATURE_FLAGS_KEY = "/api/v1/feature-flags/{featureKey}";
	public static final String FEATURE_FLAGS_EFFECTIVE = "/api/v1/feature-flags/effective";
	// Clear-first: what keeps a feature in use, and the bulk actions that clear it.
	public static final String FEATURE_FLAGS_DISABLE_CHECK = "/api/v1/feature-flags/{featureKey}/disable-check";
	public static final String FEATURE_FLAGS_CLEAR = "/api/v1/feature-flags/{featureKey}/clear";

	// DeploymentInfoController — public (unauthenticated) deployment metadata
	public static final String DEPLOYMENT_INFO = "/api/v1/deployment-info";
	// PublicStatusController — anonymous status page document, public through /api/v1/public/**.
	public static final String PUBLIC_STATUS = "/api/v1/public/status";
	/** Public keys that verify access tokens (RFC 7517 JWK set). */
	public static final String JWKS = "/.well-known/jwks.json";

	// AdminFeatureFlagController (super-admin global management)
	// Note: ADMIN_FF_SUMMARY must be mapped before ADMIN_FF_KEY in the controller
	// to prevent Spring MVC treating "summary" as a {featureKey} path variable.
	public static final String ADMIN_FF_BASE = "/api/v1/admin/feature-flags";
	public static final String ADMIN_FF_SUMMARY = "/api/v1/admin/feature-flags/summary";
	public static final String ADMIN_FF_KEY = "/api/v1/admin/feature-flags/{featureKey}";
	public static final String ADMIN_FF_OVERRIDES = "/api/v1/admin/feature-flags/{featureKey}/overrides";
	/** What switching a feature off would affect, before a super admin does it. */
	public static final String ADMIN_FF_IMPACT = "/api/v1/admin/feature-flags/{featureKey}/impact";
	public static final String ADMIN_FF_ORG_OVERRIDE = "/api/v1/admin/feature-flags/{featureKey}/overrides/{organizationId}";
	// Org-type defaults
	public static final String ADMIN_FF_ORG_TYPE_BASE = "/api/v1/admin/feature-flags/org-type/{orgType}";
	public static final String ADMIN_FF_ORG_TYPE_BULK = "/api/v1/admin/feature-flags/org-type/{orgType}/bulk";
	public static final String ADMIN_FF_ORG_TYPE_KEY = "/api/v1/admin/feature-flags/{featureKey}/org-type/{orgType}";
	// Per-org flag listing: a super admin reads the effective flags of any organization
	public static final String ADMIN_FF_ORG_FLAGS = "/api/v1/admin/feature-flags/org/{organizationId}";
	public static final String ADMIN_FEATURE_LIFECYCLE_BASELINE_PREVIEW = "/api/v1/admin/feature-lifecycle/baseline-preview";

	// DataRetentionController — org admin + super admin data retention management
	public static final String ORG_PURGE_SOFT_DELETED     = "/api/v1/organizations/{orgId}/purge-soft-deleted";
	public static final String ORG_RETENTION_SETTINGS     = "/api/v1/organizations/{orgId}/settings/soft-delete-retention";
	public static final String ADMIN_RETENTION_SETTINGS   = "/api/v1/admin/settings/soft-delete-retention";
	// NotificationSettingsController — the informational notifications an organization's admins turned off
	public static final String ORG_NOTIFICATION_SETTINGS  = "/api/v1/organizations/{orgId}/settings/notifications";
	// AuditRetentionController — super admin: how long audit events are kept
	public static final String ADMIN_AUDIT_RETENTION_SETTINGS = "/api/v1/admin/settings/audit-retention";

	// Integrations (Slack/Teams/PagerDuty/ServiceNow ITSM CRUD)
	public static final String INTEGRATIONS_BASE            = "/api/v1/integrations";
	public static final String INTEGRATIONS_ID              = "/api/v1/integrations/{integrationId}";
	// Incidents (PagerDuty + ServiceNow ITSM trigger + history)
	public static final String INCIDENTS_BASE               = "/api/v1/incidents";
	public static final String INCIDENTS_PAGERDUTY          = "/api/v1/incidents/pagerduty";
	public static final String INCIDENTS_SERVICENOW         = "/api/v1/incidents/service-now";
	// IoT device identity — MDM-sourced device registry.
	public static final String IOT_DEVICES               = "/api/v1/iot/devices";
	public static final String IOT_DEVICE_ID             = "/api/v1/iot/devices/{deviceXref}";
	public static final String IOT_DEVICE_EVENTS         = "/api/v1/iot/devices/{deviceXref}/events";
	public static final String IOT_DEVICE_CERTIFICATES   = "/api/v1/iot/devices/{deviceXref}/certificates";
	public static final String IOT_DEVICE_DECOMMISSION   = "/api/v1/iot/devices/{deviceXref}/decommission";
	public static final String IOT_DEVICE_ARCHIVE        = "/api/v1/iot/devices/{deviceXref}/archive";
	public static final String IOT_DEVICE_RESTORE        = "/api/v1/iot/devices/{deviceXref}/restore";
	public static final String IOT_SUMMARY               = "/api/v1/iot/summary";
	public static final String IOT_SOURCES               = "/api/v1/iot/sources";
	public static final String IOT_SOURCE_EVENTS         = "/api/v1/iot/sources/{sourceXref}/events";
	public static final String IOT_SOURCE_SYNC           = "/api/v1/iot/sources/{sourceXref}/sync";
	public static final String IOT_SOURCE_SYNC_STOP      = "/api/v1/iot/sources/{sourceXref}/sync/stop";
	public static final String IOT_CA_CONNECTORS         = "/api/v1/iot/ca-connectors";
	public static final String IOT_CA_CONNECTOR          = "/api/v1/iot/ca-connectors/{connectorId}";
	public static final String IOT_CERTIFICATES          = "/api/v1/iot/certificates";
	public static final String IOT_CERTIFICATE           = "/api/v1/iot/certificates/{certificateXref}";
	public static final String IOT_CERTIFICATE_HISTORY   = "/api/v1/iot/certificates/{certificateXref}/history";
	public static final String IOT_CERTIFICATE_NUDGE     = "/api/v1/iot/certificates/nudge";
	public static final String IOT_CERTIFICATE_REVOKE    = "/api/v1/iot/certificates/{certificateXref}/revoke";
	public static final String IOT_CERTIFICATE_PROFILES  = "/api/v1/machine-identity/profiles";
	public static final String IOT_CERTIFICATE_PROFILE   = "/api/v1/machine-identity/profiles/{profileXref}";
	public static final String IOT_CERTIFICATE_PROFILE_EVENTS =
			"/api/v1/machine-identity/profiles/{profileXref}/events";
	public static final String IOT_SOURCE_PROFILE_SYNC =
			"/api/v1/machine-identity/sources/{sourceXref}/profiles/sync";
}
