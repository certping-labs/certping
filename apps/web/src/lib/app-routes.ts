// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canViewCertificates,
  canViewAlerts,
  canViewNotifications,
  canViewOrganizations,
  hasOrganizationContext,
} from "@/lib/authz";
import type { SsoUser } from "@/types/auth";

export const ORGANIZATION_ACCESS_ROUTE = "/settings/organization-access";

/**
 * Where a signed-in user lands: the overview inside an organization, the
 * organizations list for a super admin without one, otherwise their own
 * account. Feature flags only decide between the alert pages.
 */
export function getDefaultAuthorizedRoute(
  user?: SsoUser | null,
  isSuperAdmin?: boolean,
  isEnabled: (key: string) => boolean = () => true,
): string {
  if (hasOrganizationContext(user)) {
    // CERTIFICATE_ISSUANCE only gates issuing new certs; viewing the dashboard
    // and existing certificate state is always available with the right permission.
    if (canViewCertificates(user)) {
      return "/dashboard";
    }

    if (isEnabled("ALERTS") && canViewAlerts(user)) {
      return "/incidents";
    }

    if (canViewNotifications(user)) {
      return "/incidents/system-notifications";
    }
  }

  if (canViewOrganizations(user, isSuperAdmin)) {
    return `${ORGANIZATION_ACCESS_ROUTE}?tab=organization`;
  }

  return `${ORGANIZATION_ACCESS_ROUTE}?tab=account`;
}
