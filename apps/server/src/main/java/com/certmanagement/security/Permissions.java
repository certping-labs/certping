// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import java.util.Set;

/**
 * Constants for all system permissions.
 * These match the permissions defined in the database.
 */
public final class Permissions {

    private Permissions() {}

    // Deployment permissions
    public static final String DEPLOYMENTS_VIEW = "deployments:view";

    // Notification permissions
    public static final String NOTIFICATIONS_VIEW = "notifications:view";

    // User management permissions
    public static final String USERS_MANAGE = "users:manage";
    public static final String USERS_VIEW = "users:view";
    public static final String USERS_CREATE = "users:create";
    public static final String USERS_DELETE = "users:delete";

    // Role management permissions
    public static final String ROLES_MANAGE = "roles:manage";
    public static final String ROLES_VIEW = "roles:view";
    public static final String ROLES_CREATE = "roles:create";
    public static final String ROLES_DELETE = "roles:delete";
    public static final String ROLES_ASSIGN = "roles:assign";

    // Permission management permissions
    public static final String PERMISSIONS_VIEW = "permissions:view";
    public static final String PERMISSIONS_ASSIGN = "permissions:assign";

    // Organization permissions
    public static final String ORGANIZATION_VIEW = "organization:view";
    public static final String ORGANIZATION_MANAGE = "organization:manage";

    // Audit permissions
    public static final String AUDIT_VIEW = "audit:view";

    // New cert lifecycle permissions
    public static final String CERTIFICATE_ISSUE  = "certificate:issue";
    public static final String CERTIFICATE_RENEW  = "certificate:renew";
    public static final String CERTIFICATE_DEPLOY = "certificate:deploy";
    public static final String CERTIFICATE_READ   = "certificate:read";
    public static final String CERTIFICATE_DELETE = "certificate:delete";
    public static final String CERTIFICATE_REVOKE = "certificate:revoke";

    /** List/get deep health checks and metrics (agent key vault path verification). */
    public static final String AGENT_DEEP_HEALTH_READ = "agent-deep-health:read";

    // Alert permissions
    public static final String ALERTS_VIEW   = "alerts:view";
    public static final String ALERTS_UPDATE = "alerts:update";

    // New credential reference permissions
    public static final String CREDENTIAL_CREATE = "credential:create";
    public static final String CREDENTIAL_READ   = "credential:read";
    public static final String CREDENTIAL_DELETE = "credential:delete";
    public static final String CREDENTIAL_ROTATE = "credential:rotate";

    // Feature flag permissions
    public static final String FEATURE_FLAGS_VIEW       = "feature_flags:view";
    public static final String FEATURE_FLAGS_MANAGE     = "feature_flags:manage";
    public static final String FEATURE_FLAGS_ADMINISTER = "feature_flags:administer";

    // Integrations and incidents.
    public static final String INTEGRATIONS_VIEW   = "integrations:view";
    public static final String INTEGRATIONS_MANAGE = "integrations:manage";
    public static final String INCIDENTS_VIEW      = "incidents:view";
    public static final String INCIDENTS_CREATE    = "incidents:create";

    // IoT device identity — MDM-sourced device registry.
    public static final String IOT_DEVICE_VIEW   = "iot_device:view";
    public static final String IOT_DEVICE_MANAGE = "iot_device:manage";
    public static final String IOT_SOURCE_VIEW   = "iot_source:view";
    public static final String IOT_SOURCE_MANAGE = "iot_source:manage";
    public static final String IOT_CA_HEALTH_VIEW = "iot_ca_health:view";
    public static final String IOT_CERTIFICATE_PROFILE_VIEW = "iot_certificate_profile:view";
    public static final String IOT_CERTIFICATE_PROFILE_MANAGE = "iot_certificate_profile:manage";
    public static final String IOT_CERTIFICATE_PROFILE_SYNC = "iot_certificate_profile:sync";

    /**
     * Permissions that act across every organization or on the platform itself. Only SUPER_ADMIN
     * holds them, and only a super admin may grant them: {@code feature_flags:administer} writes
     * global and org-type flags and any org's overrides. No other role is seeded with them.
     */
    public static final Set<String> PLATFORM_PERMISSIONS = Set.of(
            FEATURE_FLAGS_ADMINISTER);

    /**
     * Permissions that reach the organization as a whole, down to deleting or suspending it. They
     * come only with the ORGANIZATION_ADMIN role (and SUPER_ADMIN): no one but a super admin may put
     * them on a custom role or grant them directly.
     */
    public static final Set<String> ORGANIZATION_ADMIN_ONLY_PERMISSIONS = Set.of(ORGANIZATION_MANAGE);

    // Role names
    public static final String ROLE_SUPER_ADMIN = "SUPER_ADMIN";
    public static final String ROLE_ORGANIZATION_ADMIN = "ORGANIZATION_ADMIN";
    public static final String ROLE_CERT_MANAGER = "CERT_MANAGER";
    public static final String ROLE_DEPLOYMENT_MANAGER = "DEPLOYMENT_MANAGER";
    public static final String ROLE_CREDENTIALS_MANAGER = "CREDENTIALS_MANAGER";
    public static final String ROLE_VIEWER = "VIEWER";
    public static final String ROLE_NOTIFICATION_MANAGER = "NOTIFICATION_MANAGER";
    public static final String ROLE_AUDITOR                  = "AUDITOR";
    public static final String ROLE_SECURITY_ANALYST         = "SECURITY_ANALYST";
}
