// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMemo } from "react";

import { useAuth } from "@/hooks/use-auth";
import {
  hasAnyPermission,
  hasAnyRole,
  hasPermission,
  hasRole,
  isRootOrSuperAdmin,
} from "@/lib/authz";

/**
 * Central permission/role hook for UI gating.
 *
 * Reads the decoded JWT claims (`user.roles` / `user.permissions`) via
 * {@link useAuth} and exposes the {@link @/lib/authz} helpers bound to the
 * current user, so components don't each re-import them or thread `user`
 * through every call. Pair with the {@link Can} component for declarative
 * gating, or use the predicates directly for imperative checks.
 */
export function usePermissions() {
  const { user, isSuperAdmin } = useAuth();

  return useMemo(
    () => ({
      user,
      isSuperAdmin: Boolean(isSuperAdmin),
      /** True if the user holds the given `resource:action` permission. */
      can: (permission: string) => hasPermission(user, permission),
      /** True if the user holds at least one of the permissions. */
      canAny: (permissions: Iterable<string>) =>
        hasAnyPermission(user, permissions),
      /** True if the user holds every one of the permissions. */
      canAll: (permissions: Iterable<string>) => {
        for (const permission of permissions) {
          if (!hasPermission(user, permission)) {
            return false;
          }
        }
        return true;
      },
      /** True if the user has the given role name. */
      hasRole: (role: string) => hasRole(user, role),
      /** True if the user has any of the given role names. */
      hasAnyRole: (roles: Iterable<string>) => hasAnyRole(user, roles),
      /** True for platform super admins (role or auth-store flag). */
      isRootOrSuperAdmin: isRootOrSuperAdmin(user, isSuperAdmin),
    }),
    [user, isSuperAdmin],
  );
}

export type UsePermissions = ReturnType<typeof usePermissions>;
