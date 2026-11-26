// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { SsoUser } from "@/types/auth";

const SUPER_ADMIN_ROLES = new Set(["SUPER_ADMIN"]);
const ORGANIZATION_CONFIG_ROLES = new Set(["ORGANIZATION_ADMIN"]);

export const PERMISSIONS = {
  // Notifications
  notificationsView: "notifications:view",
  // Alerts
  alertsView: "alerts:view",
  alertsUpdate: "alerts:update",
  // Certificates
  certificatesView: "certificate:read",
  certificatesCreate: "certificate:issue",
  certificatesDelete: "certificate:delete",
  certificatesRevoke: "certificate:revoke",
  certificatesRenew: "certificate:renew",
  certificatesDeploy: "certificate:deploy",
  // Deployments
  deploymentsView: "deployments:view",
  // Credentials
  credentialsView: "credential:read",
  credentialsCreate: "credential:create",
  credentialsRotate: "credential:rotate",
  credentialsDelete: "credential:delete",
  // Users
  usersManage: "users:manage",
  usersView: "users:view",
  usersCreate: "users:create",
  usersDelete: "users:delete",
  // Roles
  rolesView: "roles:view",
  rolesCreate: "roles:create",
  rolesDelete: "roles:delete",
  rolesAssign: "roles:assign",
  // Permissions
  permissionsView: "permissions:view",
  permissionsAssign: "permissions:assign",
  // Organization
  organizationView: "organization:view",
  organizationManage: "organization:manage",
  // Audit
  auditView: "audit:view",
  // Integrations
  integrationsView: "integrations:view",
  integrationsManage: "integrations:manage",
  // Incidents
  incidentsView: "incidents:view",
  incidentsCreate: "incidents:create",
  // Machine Identity (IoT device registry, certificates, and profiles)
  iotDeviceView: "iot_device:view",
  iotDeviceManage: "iot_device:manage",
  iotSourceView: "iot_source:view",
  iotSourceManage: "iot_source:manage",
  iotCaHealthView: "iot_ca_health:view",
  iotCertificateProfileView: "iot_certificate_profile:view",
  iotCertificateProfileManage: "iot_certificate_profile:manage",
  iotCertificateProfileSync: "iot_certificate_profile:sync",
} as const;

export const hasRole = (
  user: SsoUser | null | undefined,
  role: string,
): boolean => Boolean(user?.roles?.includes(role));

export const hasAnyRole = (
  user: SsoUser | null | undefined,
  roles: Iterable<string>,
): boolean => {
  if (!user?.roles?.length) {
    return false;
  }

  for (const role of roles) {
    if (user.roles.includes(role)) {
      return true;
    }
  }

  return false;
};

export const hasPermission = (
  user: SsoUser | null | undefined,
  permission: string,
): boolean => {
  if (!user?.permissions?.length) {
    return false;
  }

  return (
    user.permissions.includes("*") || user.permissions.includes(permission)
  );
};

export const hasAnyPermission = (
  user: SsoUser | null | undefined,
  permissions: Iterable<string>,
): boolean => {
  for (const permission of permissions) {
    if (hasPermission(user, permission)) {
      return true;
    }
  }
  return false;
};

export const isRootOrSuperAdmin = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  return Boolean(isSuperAdmin) || hasAnyRole(user, SUPER_ADMIN_ROLES);
};

export const hasOrganizationContext = (
  user: SsoUser | null | undefined,
): boolean => {
  const organizationId = user?.organizationId;
  if (organizationId == null) return false;
  return Boolean(String(organizationId).trim());
};

const hasScopedPermission = (
  user: SsoUser | null | undefined,
  permission: string,
): boolean => {
  return hasPermission(user, permission);
};

const hasOrganizationScopedPermission = (
  user: SsoUser | null | undefined,
  permission: string,
): boolean => {
  return hasOrganizationContext(user) && hasPermission(user, permission);
};

const hasAnyOrganizationScopedPermission = (
  user: SsoUser | null | undefined,
  permissions: Iterable<string>,
): boolean => {
  return hasOrganizationContext(user) && hasAnyPermission(user, permissions);
};

export const canManageOrganizations = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  return isRootOrSuperAdmin(user, isSuperAdmin);
};

export const canViewOrganizations = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return (
    hasAnyRole(user, ORGANIZATION_CONFIG_ROLES) ||
    hasAnyPermission(user, [
      PERMISSIONS.organizationView,
      PERMISSIONS.organizationManage,
    ])
  );
};

export const canUpdateOrganizations = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return (
    hasAnyRole(user, ORGANIZATION_CONFIG_ROLES) ||
    hasPermission(user, PERMISSIONS.organizationManage)
  );
};

/**
 * The Agents page: the same permission that lists and creates agent tokens on the organization
 * page, inside an organization (agents belong to one).
 */
export const canManageAgents = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean =>
  hasOrganizationContext(user) && canUpdateOrganizations(user, isSuperAdmin);

export const canConfigureOrganizationSettings = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  return canUpdateOrganizations(user, isSuperAdmin);
};

/**
 * The notification settings page. The server serves it to holders of
 * `organization:manage` on the organization, a permission only organization
 * admins carry; super admins may read it for support.
 */
export const canViewNotificationSettings = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  return (
    isRootOrSuperAdmin(user, isSuperAdmin) ||
    hasOrganizationScopedPermission(user, PERMISSIONS.organizationManage)
  );
};

/** Only the organization's own admins change what it is sent; a super admin never does. */
export const canChangeNotificationSettings = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  return (
    !isRootOrSuperAdmin(user, isSuperAdmin) &&
    hasOrganizationScopedPermission(user, PERMISSIONS.organizationManage)
  );
};

export const canSwitchOrganizationContext = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  return isRootOrSuperAdmin(user, isSuperAdmin);
};

export const canViewCertificates = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesView);
};

export const canCreateCertificates = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesCreate);
};

export const canDeleteCertificates = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesDelete);
};

/**
 * Discovery scans dispatch commands to the agent, so the backend guards
 * triggering and rerunning them with `certificate:deploy`, not `certificate:issue`.
 */
export const canTriggerDiscovery = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesDeploy);
};

/** Removing a saved discovery configuration requires `certificate:delete`. */
export const canDeleteDiscoveryConfigs = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesDelete);
};

export const canRevokeCertificates = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesRevoke);
};

export const canRenewCertificates = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesRenew);
};

/**
 * Downloading a private key (PEM key or PFX) lets the holder install the
 * certificate anywhere, so the backend guards those export formats with
 * `certificate:deploy`; the certificate and chain need only `certificate:read`.
 */
export const canExportPrivateKey = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesDeploy);
};

export const canViewDeployments = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.deploymentsView);
};

export const canCreateDeployments = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.certificatesDeploy);
};

export const canViewCredentials = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.credentialsView);
};

export const canCreateCredentials = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.credentialsCreate);
};

export const canManageCredentials = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasAnyOrganizationScopedPermission(user, [
    PERMISSIONS.credentialsDelete,
    PERMISSIONS.credentialsCreate,
    PERMISSIONS.credentialsRotate,
  ]);
};

export const canUpdateCredentials = (
  user: SsoUser | null | undefined,
): boolean => {
  return canManageCredentials(user);
};

export const canDeleteCredentials = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.credentialsDelete);
};

export const canRotateCredentials = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.credentialsRotate);
};

export const canViewUsers = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return hasScopedPermission(user, PERMISSIONS.usersView);
};

export const canManageUsers = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return hasScopedPermission(user, PERMISSIONS.usersManage);
};

export const canViewRoles = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return hasScopedPermission(user, PERMISSIONS.rolesView);
};

export const canManageRoles = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return (
    hasScopedPermission(user, PERMISSIONS.rolesCreate) ||
    hasScopedPermission(user, PERMISSIONS.rolesDelete)
  );
};

export const canDeleteRoles = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return hasScopedPermission(user, PERMISSIONS.rolesDelete);
};

export const canManageTeam = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return (
    canManageUsers(user) ||
    canManageRoles(user) ||
    canViewUsers(user) ||
    canViewRoles(user)
  );
};

export const canViewAudit = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean => {
  void isSuperAdmin;
  return hasScopedPermission(user, PERMISSIONS.auditView);
};

/**
 * The server's platform audit route (`/api/v1/admin/audit-logs`): the super
 * admin role and audit:view, with or without an organization.
 */
export const canViewPlatformAudit = (
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean =>
  isRootOrSuperAdmin(user, isSuperAdmin) &&
  hasPermission(user, PERMISSIONS.auditView);

/** The server's customer audit routes: audit:view inside an organization. */
export const canViewOrganizationAudit = (
  user: SsoUser | null | undefined,
): boolean => hasOrganizationScopedPermission(user, PERMISSIONS.auditView);

/** Alerts (`/api/alerts`): notifications:view or alerts:view inside an organization. */
export const canViewAlerts = (user: SsoUser | null | undefined): boolean => {
  return (
    hasOrganizationContext(user) &&
    (hasPermission(user, PERMISSIONS.notificationsView) ||
      hasPermission(user, PERMISSIONS.alertsView))
  );
};

/**
 * The system notifications list (`/api/notifications`). The server requires
 * organization:manage, so VIEWER and SECURITY_ANALYST (403) do not see it.
 */
export const canViewNotifications = (
  user: SsoUser | null | undefined,
): boolean => {
  return (
    hasOrganizationContext(user) &&
    hasPermission(user, PERMISSIONS.organizationManage)
  );
};

export const canManageNotifications = (
  user: SsoUser | null | undefined,
): boolean => {
  return (
    hasOrganizationContext(user) &&
    hasPermission(user, PERMISSIONS.alertsUpdate)
  );
};

export const canViewIntegrations = (
  user: SsoUser | null | undefined,
): boolean => {
  // Org-scoped like the server's check: a super admin with no organization
  // context sees nothing, while the self-hosted first admin (super admin and
  // Organization Admin of the one organization) sees the organization's apps.
  return hasOrganizationScopedPermission(user, PERMISSIONS.integrationsView);
};

export const canManageIntegrations = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.integrationsManage);
};

// ── Incidents ───────────────────────────────────────────────────────

export const canViewIncidents = (user: SsoUser | null | undefined): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.incidentsView);
};

export const canCreateIncidents = (
  user: SsoUser | null | undefined,
): boolean => {
  return hasOrganizationScopedPermission(user, PERMISSIONS.incidentsCreate);
};
