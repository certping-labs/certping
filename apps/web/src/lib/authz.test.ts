// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canConfigureOrganizationSettings,
  canCreateCredentials,
  canCreateDeployments,
  canDeleteCertificates,
  canDeleteDiscoveryConfigs,
  canDeleteRoles,
  canExportPrivateKey,
  canChangeNotificationSettings,
  canViewNotificationSettings,
  canManageCredentials,
  canManageNotifications,
  canManageRoles,
  canManageTeam,
  canManageUsers,
  canRevokeCertificates,
  canRotateCredentials,
  canUpdateCredentials,
  canViewIntegrations,
  canViewRoles,
  canViewUsers,
  hasPermission,
  canCreateCertificates,
  canManageOrganizations,
  canSwitchOrganizationContext,
  canTriggerDiscovery,
  canUpdateOrganizations,
  canViewAudit,
  canViewCertificates,
  canViewCredentials,
  canViewDeployments,
  canViewAlerts,
  canViewNotifications,
  canViewOrganizations,
  canViewIncidents,
  canCreateIncidents,
  canManageIntegrations,
  hasOrganizationContext,
  isRootOrSuperAdmin,
} from "@/lib/authz";
import type { SsoUser } from "@/types/auth";

function createUser(overrides: Partial<SsoUser>): SsoUser {
  return {
    id: "user-1",
    email: "user@example.com",
    organizationId: null,
    organizationName: null,
    roles: [],
    permissions: [],
    authMethod: "LOCAL",
    ...overrides,
  };
}

describe("authz", () => {
  it("treats SUPER_ADMIN as the root/global admin path", () => {
    const user = createUser({
      email: "super-admin@example.com",
      roles: ["SUPER_ADMIN"],
      permissions: [
        "organization:view",
        "organization:manage",
        "audit:view",
        "certificate:read",
        "credential:read",
        "deployments:view",
        "notifications:view",
      ],
    });

    expect(isRootOrSuperAdmin(user)).toBe(true);
    expect(hasOrganizationContext(user)).toBe(false);
    expect(canSwitchOrganizationContext(user)).toBe(true);
    expect(canViewOrganizations(user)).toBe(true);
    expect(canManageOrganizations(user)).toBe(true);
    expect(canViewAudit(user)).toBe(true);

    expect(canViewCertificates(user)).toBe(false);
    expect(canCreateCertificates(user)).toBe(false);
    expect(canViewDeployments(user)).toBe(false);
    expect(canViewCredentials(user)).toBe(false);
    expect(canViewNotifications(user)).toBe(false);
  });

  it("keeps organization admins scoped to their organization", () => {
    const user = createUser({
      email: "organization-admin@example.com",
      organizationId: "organization-123",
      organizationName: "Acme",
      roles: ["ORGANIZATION_ADMIN"],
      permissions: [
        "organization:view",
        "organization:manage",
        "certificate:read",
        "certificate:issue",
        "deployments:view",
        "credential:read",
        "notifications:view",
      ],
    });

    expect(isRootOrSuperAdmin(user)).toBe(false);
    expect(hasOrganizationContext(user)).toBe(true);
    expect(canSwitchOrganizationContext(user)).toBe(false);

    expect(canViewOrganizations(user)).toBe(true);
    expect(canUpdateOrganizations(user)).toBe(true);
    expect(canManageOrganizations(user)).toBe(false);

    expect(canViewCertificates(user)).toBe(true);
    expect(canCreateCertificates(user)).toBe(true);
    expect(canViewDeployments(user)).toBe(true);
    expect(canViewCredentials(user)).toBe(true);
    expect(canViewNotifications(user)).toBe(true);
  });

  it("supports wildcard permissions and scoped management functions", () => {
    const user = createUser({
      organizationId: "organization-1",
      permissions: ["*"],
    });

    expect(hasPermission(user, "anything")).toBe(true);
    expect(canDeleteCertificates(user)).toBe(true);
    expect(canRevokeCertificates(user)).toBe(true);
    expect(canCreateDeployments(user)).toBe(true);
    expect(canCreateCredentials(user)).toBe(true);
    expect(canManageCredentials(user)).toBe(true);
    expect(canUpdateCredentials(user)).toBe(true);
    expect(canRotateCredentials(user)).toBe(true);
    expect(canManageNotifications(user)).toBe(true);
  });

  it("validates user/role/team access controls", () => {
    const user = createUser({
      permissions: ["users:view", "roles:delete"],
    });

    expect(canViewUsers(user)).toBe(true);
    expect(canManageUsers(user)).toBe(false);
    expect(canViewRoles(user)).toBe(false);
    expect(canManageRoles(user)).toBe(true);
    expect(canDeleteRoles(user)).toBe(true);
    expect(canManageTeam(user)).toBe(true);
    expect(canConfigureOrganizationSettings(user)).toBe(false);
  });

  it("applies notification and integration visibility constraints", () => {
    const orgAlertsUser = createUser({
      organizationId: "organization-1",
      permissions: ["alerts:view"],
    });
    expect(canViewAlerts(orgAlertsUser)).toBe(true);
    // The notifications list needs organization:manage (server returns 403 otherwise).
    expect(canViewNotifications(orgAlertsUser)).toBe(false);

    const noContextUser = createUser({
      permissions: ["notifications:view"],
    });
    expect(canViewAlerts(noContextUser)).toBe(false);
    expect(canViewNotifications(noContextUser)).toBe(false);

    for (const role of ["VIEWER", "SECURITY_ANALYST"]) {
      const reader = createUser({
        organizationId: "organization-1",
        roles: [role],
        permissions: ["organization:view", "notifications:view", "alerts:view"],
      });
      expect(canViewAlerts(reader)).toBe(true);
      expect(canViewNotifications(reader)).toBe(false);
    }

    const orgManager = createUser({
      organizationId: "organization-1",
      permissions: ["organization:manage"],
    });
    expect(canViewNotifications(orgManager)).toBe(true);

    const superAdmin = createUser({ roles: ["SUPER_ADMIN"] });
    expect(canViewIntegrations(superAdmin)).toBe(false);
    // Integrations are org-scoped: a user without org context (and without the
    // integrations:view permission) cannot see them.
    expect(canViewIntegrations(noContextUser)).toBe(false);

    const orgIntegrationsUser = createUser({
      organizationId: "organization-1",
      permissions: ["integrations:view"],
    });
    expect(canViewIntegrations(orgIntegrationsUser)).toBe(true);
    expect(canManageIntegrations(orgIntegrationsUser)).toBe(false);

    const orgIntegrationManager = createUser({
      organizationId: "organization-1",
      permissions: ["integrations:view", "integrations:manage"],
    });
    expect(canViewIntegrations(orgIntegrationManager)).toBe(true);
    expect(canManageIntegrations(orgIntegrationManager)).toBe(true);

    // The self-hosted first admin holds both roles in its one organization.
    const selfHostedAdmin = createUser({
      roles: ["SUPER_ADMIN", "ORGANIZATION_ADMIN"],
      organizationId: "organization-1",
      permissions: ["integrations:view", "integrations:manage"],
    });
    expect(canViewIntegrations(selfHostedAdmin)).toBe(true);
  });

  it("gates incidents on org-scoped permissions", () => {
    const supportViewer = createUser({
      organizationId: "organization-1",
      permissions: ["incidents:view"],
    });
    expect(canViewIncidents(supportViewer)).toBe(true);
    expect(canCreateIncidents(supportViewer)).toBe(false);

    const supportManager = createUser({
      organizationId: "organization-1",
      permissions: ["incidents:view", "incidents:create"],
    });
    expect(canViewIncidents(supportManager)).toBe(true);
    expect(canCreateIncidents(supportManager)).toBe(true);

    const noContextUser = createUser({
      permissions: ["incidents:view", "incidents:create"],
    });
    expect(canViewIncidents(noContextUser)).toBe(false);
    expect(canCreateIncidents(noContextUser)).toBe(false);
  });

  it("guards discovery runs with certificate:deploy and removals with certificate:delete", () => {
    const issuer = createUser({
      organizationId: "org-1",
      permissions: ["certificate:read", "certificate:issue"],
    });
    const deployer = createUser({
      organizationId: "org-1",
      permissions: ["certificate:deploy"],
    });
    const remover = createUser({
      organizationId: "org-1",
      permissions: ["certificate:delete"],
    });

    expect(canTriggerDiscovery(issuer)).toBe(false);
    expect(canDeleteDiscoveryConfigs(issuer)).toBe(false);
    expect(canTriggerDiscovery(deployer)).toBe(true);
    expect(canDeleteDiscoveryConfigs(deployer)).toBe(false);
    expect(canTriggerDiscovery(remover)).toBe(false);
    expect(canDeleteDiscoveryConfigs(remover)).toBe(true);
    expect(
      canTriggerDiscovery(createUser({ permissions: ["certificate:deploy"] })),
    ).toBe(false);
  });

  it("offers private-key exports only to certificate:deploy holders in an organization", () => {
    const viewer = createUser({
      organizationId: "org-1",
      permissions: ["certificate:read"],
    });
    const deployer = createUser({
      organizationId: "org-1",
      permissions: ["certificate:read", "certificate:deploy"],
    });

    expect(canExportPrivateKey(viewer)).toBe(false);
    expect(canExportPrivateKey(deployer)).toBe(true);
    expect(
      canExportPrivateKey(createUser({ permissions: ["certificate:deploy"] })),
    ).toBe(false);
    expect(canExportPrivateKey(null)).toBe(false);
  });

  it("lets organization admins change notification settings and super admins only read them", () => {
    const orgAdmin = createUser({
      organizationId: "7",
      roles: ["ORGANIZATION_ADMIN"],
      permissions: ["organization:manage"],
    });
    const viewer = createUser({
      organizationId: "7",
      permissions: ["organization:view"],
    });

    expect(canViewNotificationSettings(orgAdmin)).toBe(true);
    expect(canChangeNotificationSettings(orgAdmin)).toBe(true);
    expect(canViewNotificationSettings(viewer)).toBe(false);
    expect(canChangeNotificationSettings(viewer)).toBe(false);
    expect(canViewNotificationSettings(createUser({}), true)).toBe(true);
    expect(canChangeNotificationSettings(orgAdmin, true)).toBe(false);
    expect(
      canViewNotificationSettings(
        createUser({
          organizationId: null,
          permissions: ["organization:manage"],
        }),
      ),
    ).toBe(false);
    expect(canViewNotificationSettings(undefined)).toBe(false);
  });
});
