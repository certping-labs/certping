// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A member's access is the union of what their roles grant and the permissions
 * granted to them directly. Direct grants are only the extras an admin picked
 * on top of the roles, so dropping a role also drops everything it provided.
 */

export type RolePermissionsById = ReadonlyMap<string, readonly string[]>;

export interface RoleProvidedPermission {
  name: string;
  roleIds: string[];
}

export interface MemberAccessBaseline {
  roleIds: readonly string[];
  /** The member's stored direct grants, or null when they could not be read. */
  directPermissionNames: readonly string[] | null;
}

export interface MemberAccessSelection {
  roleIds: readonly string[];
  extraPermissionNames: readonly string[];
}

export interface MemberAccessChanges {
  /** Role ids to assign, or null when the selected roles are unchanged. */
  roleIds: number[] | null;
  /** The full direct grant set to store, or null when it is unchanged. */
  directPermissionNames: string[] | null;
}

export type MemberSaveStep = "profile" | "roles" | "directGrants";

export interface MemberSaveActions {
  updateProfile: () => Promise<unknown>;
  assignRoles: (roleIds: number[]) => Promise<unknown>;
  setDirectGrants: (permissionNames: string[]) => Promise<unknown>;
}

export type MemberSaveResult =
  | { ok: true; savedSteps: MemberSaveStep[] }
  | {
      ok: false;
      savedSteps: MemberSaveStep[];
      failedStep: MemberSaveStep;
      error: unknown;
    };

const uniqueSorted = (values: Iterable<string>): string[] =>
  Array.from(new Set(values)).sort();

const haveSameMembers = (
  left: readonly string[],
  right: readonly string[],
): boolean => {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  if (leftSet.size !== rightSet.size) {
    return false;
  }
  for (const value of leftSet) {
    if (!rightSet.has(value)) {
      return false;
    }
  }
  return true;
};

export const getRoleProvidedPermissions = (
  roleIds: readonly string[],
  rolePermissionsById: RolePermissionsById,
): RoleProvidedPermission[] => {
  const roleIdsByPermission = new Map<string, string[]>();

  for (const roleId of new Set(roleIds)) {
    for (const permissionName of rolePermissionsById.get(roleId) ?? []) {
      const sources = roleIdsByPermission.get(permissionName);
      if (sources) {
        sources.push(roleId);
      } else {
        roleIdsByPermission.set(permissionName, [roleId]);
      }
    }
  }

  return Array.from(roleIdsByPermission, ([name, sourceRoleIds]) => ({
    name,
    roleIds: sourceRoleIds,
  })).sort((left, right) => left.name.localeCompare(right.name));
};

export const getRoleProvidedPermissionNames = (
  roleIds: readonly string[],
  rolePermissionsById: RolePermissionsById,
): Set<string> =>
  new Set(
    getRoleProvidedPermissions(roleIds, rolePermissionsById).map(
      (permission) => permission.name,
    ),
  );

/** Direct grants that are not already covered by the given roles. */
export const getExtraPermissionNames = (
  permissionNames: readonly string[],
  roleIds: readonly string[],
  rolePermissionsById: RolePermissionsById,
): string[] => {
  const roleProvided = getRoleProvidedPermissionNames(
    roleIds,
    rolePermissionsById,
  );
  return uniqueSorted(
    permissionNames.filter(
      (permissionName) => !roleProvided.has(permissionName),
    ),
  );
};

const toNumericRoleIds = (roleIds: readonly string[]): number[] =>
  uniqueSorted(roleIds)
    .map((roleId) => Number(roleId))
    .filter((roleId) => Number.isInteger(roleId) && roleId > 0);

export const planMemberAccessChanges = (
  baseline: MemberAccessBaseline,
  selection: MemberAccessSelection,
  rolePermissionsById: RolePermissionsById,
): MemberAccessChanges => {
  const roleIds = haveSameMembers(baseline.roleIds, selection.roleIds)
    ? null
    : toNumericRoleIds(selection.roleIds);

  if (baseline.directPermissionNames === null) {
    return { roleIds, directPermissionNames: null };
  }

  const nextDirectPermissionNames = getExtraPermissionNames(
    selection.extraPermissionNames,
    selection.roleIds,
    rolePermissionsById,
  );

  return {
    roleIds,
    directPermissionNames: haveSameMembers(
      baseline.directPermissionNames,
      nextDirectPermissionNames,
    )
      ? null
      : nextDirectPermissionNames,
  };
};

/**
 * Saves the profile, then the roles, then the direct grants, stopping at the
 * first failure. Direct grants go last because they are planned against the
 * new role set, and a role change can itself rewrite the stored grants.
 */
export const saveMemberEdit = async (
  changes: MemberAccessChanges,
  actions: MemberSaveActions,
): Promise<MemberSaveResult> => {
  const steps: Array<[MemberSaveStep, () => Promise<unknown>]> = [
    ["profile", actions.updateProfile],
  ];
  const { roleIds, directPermissionNames } = changes;
  if (roleIds !== null) {
    steps.push(["roles", () => actions.assignRoles(roleIds)]);
  }
  if (directPermissionNames !== null) {
    steps.push([
      "directGrants",
      () => actions.setDirectGrants(directPermissionNames),
    ]);
  }

  const savedSteps: MemberSaveStep[] = [];
  for (const [step, run] of steps) {
    try {
      await run();
    } catch (error) {
      return { ok: false, savedSteps, failedStep: step, error };
    }
    savedSteps.push(step);
  }
  return { ok: true, savedSteps };
};

const STEP_FAILURE_LABELS: Record<MemberSaveStep, string> = {
  profile: "Failed to update member",
  roles: "Roles were not updated",
  directGrants: "Additional permissions were not updated",
};

const describeSavedSteps = (savedSteps: readonly MemberSaveStep[]) => {
  if (savedSteps.includes("roles")) {
    return "Profile and roles saved. ";
  }
  return savedSteps.includes("profile") ? "Profile saved. " : "";
};

export const describeMemberSaveFailure = (
  result: Extract<MemberSaveResult, { ok: false }>,
  detail: string,
): string =>
  `${describeSavedSteps(result.savedSteps)}${STEP_FAILURE_LABELS[result.failedStep]}${detail ? `: ${detail}` : ""}`;
