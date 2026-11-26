// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getDefaultAuthorizedRoute } from "@/lib/app-routes";
import type { AuthSession, SsoUser } from "@/types/auth";

/** The Your account tab, opened on its password form. */
export const REQUIRED_PASSWORD_CHANGE_ROUTE =
  "/settings/organization-access?tab=account&changePassword=true";

export function isMandatoryPostAuthRoute(route: string): boolean {
  return route === REQUIRED_PASSWORD_CHANGE_ROUTE;
}

/** A member flagged by an administrator must set a new password first. */
export function shouldRequirePasswordChange(
  user: SsoUser | null | undefined,
  isSuperAdmin?: boolean,
): boolean {
  // A super admin without an organization has no account page to change it on;
  // every other account (including the first admin, who always has one) must.
  return (
    Boolean(user?.mustChangePassword) &&
    (!isSuperAdmin || Boolean(user?.organizationId))
  );
}

/** Where a fresh session lands: the password form when one is owed, else the default page. */
export function getPostAuthRoute(session: AuthSession): string {
  if (shouldRequirePasswordChange(session.user, session.isSuperAdmin)) {
    return REQUIRED_PASSWORD_CHANGE_ROUTE;
  }
  return getDefaultAuthorizedRoute(session.user, session.isSuperAdmin);
}
