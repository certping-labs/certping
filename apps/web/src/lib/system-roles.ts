// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The four system roles of the open edition, as the backend seeds them.
 * Custom organization roles exist beside these and carry their own
 * descriptions; only these four have fixed copy in the UI.
 */
export interface SystemRole {
  name: string;
  label: string;
  description: string;
}

export const SYSTEM_ROLES: readonly SystemRole[] = [
  {
    name: "SUPER_ADMIN",
    label: "Platform Super Admin",
    description:
      "Global platform administration: creates, suspends and manages organizations, owns platform configuration and reads the platform-wide audit log.",
  },
  {
    name: "ORGANIZATION_ADMIN",
    label: "Organization Admin",
    description:
      "Manages one organization and its settings: invites, removes and assigns members; configures discovery, PQC, rotation, deployments and credentials; views the organization's audit log.",
  },
  {
    name: "SECURITY_ANALYST",
    label: "Security Analyst",
    description:
      "Views the certificate inventory, discovery results, expiry, risk, algorithm and PQC readiness, rotation and deployment status; runs discovery, rotation and deployments that an admin configured; acknowledges alerts. Cannot manage members, credentials, integrations or platform settings.",
  },
  {
    name: "VIEWER",
    label: "Viewer",
    description:
      "Read-only access to certificates, discovery, PQC readiness, rotation, deployments and audit information.",
  },
];

const BY_NAME = new Map(SYSTEM_ROLES.map((role) => [role.name, role]));

export function findSystemRole(name: string | null | undefined) {
  return name ? BY_NAME.get(name) : undefined;
}

export function isSystemRole(name: string | null | undefined): boolean {
  return Boolean(findSystemRole(name));
}
