// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canManageAgents,
  canManageTeam,
  canViewAudit,
  canViewNotificationSettings,
  canViewOrganizations,
} from "@/lib/authz";
import {
  type AppSearchContext,
  type AppSearchItem,
  createAppSearchItem,
} from "@/lib/app-search-types";
import { FEATURE_FLAGS } from "@/lib/feature-flags";

const ORGANIZATION_ACCESS = "/settings/organization-access";

export function getAdministrationSearchItems({
  hasOrganization,
  isFeatureEnabled,
  isSuperAdmin,
  user,
}: AppSearchContext): AppSearchItem[] {
  const items: AppSearchItem[] = [
    createAppSearchItem(
      "Organization & Access",
      "Your organization, its members and roles, your account and notifications.",
      ORGANIZATION_ACCESS,
      "Administration",
      ["settings", "access", "organization", "members"],
    ),
    createAppSearchItem(
      "Your account",
      "Manage profile, authentication, and password settings.",
      `${ORGANIZATION_ACCESS}?tab=account`,
      "Administration",
      ["profile", "user", "password", "account"],
    ),
  ];

  if (isSuperAdmin || user?.authMethod === "LOCAL") {
    items.push(
      createAppSearchItem(
        "Change Password",
        "Open account security settings.",
        `${ORGANIZATION_ACCESS}?tab=account&changePassword=true`,
        "Administration",
        ["change password", "update password", "reset password", "security"],
      ),
    );
  }

  if (canManageTeam(user, isSuperAdmin)) {
    items.push(
      createAppSearchItem(
        "Members & roles",
        "Manage users, roles, and access.",
        `${ORGANIZATION_ACCESS}?tab=members`,
        "Administration",
        [
          "team",
          "roles",
          "permissions",
          "users",
          "members",
          "add member",
          "invite user",
          "create role",
        ],
      ),
    );
  }

  // Same gate as the Agents item in the sidebar: the permission that manages agent tokens.
  if (canManageAgents(user, isSuperAdmin)) {
    items.push(
      createAppSearchItem(
        "Agents",
        "Every agent of the organization, its settings, and Add agent.",
        "/agents",
        "Administration",
        ["agent", "agents", "add agent", "agent token", "install agent"],
      ),
    );
  }

  if (canViewOrganizations(user, isSuperAdmin)) {
    items.push(
      createAppSearchItem(
        isSuperAdmin ? "Organizations" : "Organization",
        "Manage organization settings and context.",
        `${ORGANIZATION_ACCESS}?tab=organization`,
        "Administration",
        ["tenant", "company", "org"],
      ),
    );
  }

  if (
    hasOrganization &&
    isFeatureEnabled(FEATURE_FLAGS.NOTIFICATION_PREFERENCES) &&
    canViewNotificationSettings(user, isSuperAdmin)
  ) {
    items.push(
      createAppSearchItem(
        "Notification preferences",
        "Choose which informational notifications are sent.",
        `${ORGANIZATION_ACCESS}?tab=notifications`,
        "Administration",
        ["notifications", "emails", "alerts", "slack", "teams", "mute"],
      ),
    );
  }

  if (canViewAudit(user, isSuperAdmin)) {
    items.push(
      createAppSearchItem(
        "Audit",
        "Who changed what, and when.",
        `${ORGANIZATION_ACCESS}?tab=audit`,
        "Administration",
        ["audit", "log", "history", "compliance"],
      ),
    );
  }

  items.push(
    createAppSearchItem(
      "Support",
      "How to get help with CertPing.",
      "/support",
      "Administration",
      ["help", "service", "contact support"],
    ),
  );

  return items;
}
