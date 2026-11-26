// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { toast } from "sonner";

import { Unauthorised } from "@/components/common/unautorised";
import {
  RolesPanel,
  type CreateRoleState,
  type DeleteRoleState,
  type EditRoleState,
} from "@/components/settings/teams/roles-panel";

import { CustomTable } from "@/components/ui/custom-table";
import { FilterSelectChip } from "@/components/ui/filter-select-chip";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";
import { useAuth } from "@/hooks/use-auth";
import { useFeatureFlags } from "@/hooks/use-feature-flags";
import { ACCESS_SAVE_WAITING_REASON } from "@/components/settings/teams/access-save-blocked-note";
import { RoleDescriptions } from "@/components/settings/teams/role-descriptions";
import {
  useAssignUserRoles,
  useCreateRole,
  getApiErrorMessage,
  useDeleteRole,
  useCreateUser,
  useDeleteUser,
  useDisableUser,
  useGetRolePermissions,
  useGetUserPermissions,
  useListRoles,
  useListPermissions,
  useListUsers,
  useUpdateRolePermissions,
  useUpdateUser,
  useUpdateUserPermissions,
} from "@/hooks/users";
import { useOrganizations } from "@/hooks/organizations";
import { resetMemberMfa } from "@/lib/backend/auth";
import { getOrganizationIdValue } from "@/lib/backend/organizations";
import {
  canDeleteRoles,
  canManageRoles,
  canManageTeam,
  canManageUsers,
  canViewRoles,
  canViewUsers,
  isRootOrSuperAdmin,
} from "@/lib/authz";
import type { UserDto } from "@/types/auth";
import {
  createUserColumns,
  formatRoleName,
  MemberCard,
} from "@/components/settings/teams/user-table";
import {
  DeleteUserDialog,
  InviteUserDialog,
  type DeleteUserState,
  type InviteUserValues,
} from "@/components/settings/teams/user-dialogs";
import {
  EditUserDialog,
  type DirectGrantsState,
  type EditUserState,
  type EditUserValues,
} from "@/components/settings/teams/edit-user-dialog";
import {
  describeMemberSaveFailure,
  planMemberAccessChanges,
  saveMemberEdit,
} from "@/lib/member-access";

const EMPTY_CREATE_ROLE_FORM: CreateRoleState = {
  name: "",
  description: "",
  permissionNames: [],
};

const resolveRoleIds = (
  roleNames: string[] | undefined,
  roles: Array<{ id: number; name: string }> | undefined,
): string[] => {
  if (!roleNames?.length || !roles?.length) {
    return [];
  }

  const idsByName = new Map(roles.map((role) => [role.name, String(role.id)]));
  return roleNames
    .map((roleName) => idsByName.get(roleName))
    .filter((value): value is string => Boolean(value));
};

const areStringArraysEqual = (left: string[], right: string[]) => {
  if (left.length !== right.length) {
    return false;
  }

  return left.every((value, index) => value === right[index]);
};

const buildEditUserState = (
  user: UserDto,
  roles: Array<{ id: number; name: string }> | undefined,
): EditUserState => ({
  id: user.id,
  displayName: user.displayName ?? "",
  email: user.email,
  username: user.username ?? "",
  roleIds: resolveRoleIds(user.roles, roles),
  active: user.active !== false,
});

const isSameUser = (
  candidate: Pick<UserDto, "id"> & { email?: string },
  currentUser: Pick<UserDto, "id" | "email"> | null | undefined,
) => {
  if (!currentUser) {
    return false;
  }

  if (
    currentUser.id !== undefined &&
    currentUser.id !== null &&
    String(candidate.id) === String(currentUser.id)
  ) {
    return true;
  }

  if (!candidate.email || !currentUser.email) {
    return false;
  }

  return candidate.email.toLowerCase() === currentUser.email.toLowerCase();
};

const MEMBER_SEARCH_KEYS = ["email", "username", "displayName", "id"];
const getMemberRowId = (row: UserDto) => String(row.id);
const AUTH_FILTER_OPTIONS = [
  { label: "Any sign-in", value: "all" },
  { label: "Password", value: "LOCAL" },
  { label: "SSO", value: "SSO" },
];
const STATUS_FILTER_OPTIONS = [
  { label: "Any status", value: "all" },
  { label: "Active", value: "active" },
  { label: "Disabled", value: "disabled" },
];

/** The Members & roles tab: members, invitations, roles and direct grants. */
export function MembersPanel() {
  const { user, isSuperAdmin, isLoading: isLoadingAuth } = useAuth();
  const canManage = canManageTeam(user, isSuperAdmin);
  const canManageMembers = canManageUsers(user, isSuperAdmin);
  const canViewMembers = canViewUsers(user, isSuperAdmin);
  const canManageRoleDefs = canManageRoles(user, isSuperAdmin);
  const canViewRoleDefs = canViewRoles(user, isSuperAdmin);
  const canDeleteRoleDefs = canDeleteRoles(user, isSuperAdmin);
  const canSeeMembers = canManageMembers || canViewMembers;
  const canSeeRoles = canManageRoleDefs || canViewRoleDefs;
  const organizationScoped =
    !isRootOrSuperAdmin(user, isSuperAdmin) && Boolean(user?.organizationId);
  // The backend hides roles and permissions of features that are off and
  // keeps them on save, so the pickers show exactly what it returns. Only
  // while the flag answer is still loading do access saves wait.
  const { isReady: areFeatureFlagsReady } = useFeatureFlags();
  const accessSaveBlockedReason = areFeatureFlagsReady
    ? null
    : ACCESS_SAVE_WAITING_REASON;

  const [activeTab, setActiveTab] = useState(
    canSeeMembers ? "members" : "roles",
  );
  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [isCreateRoleOpen, setIsCreateRoleOpen] = useState(false);
  const [createRoleForm, setCreateRoleForm] = useState<CreateRoleState>(
    EMPTY_CREATE_ROLE_FORM,
  );
  const [editUser, setEditUser] = useState<EditUserState | null>(null);
  const [deleteUser, setDeleteUser] = useState<DeleteUserState | null>(null);
  const [editRole, setEditRole] = useState<EditRoleState | null>(null);
  const [deleteRoleState, setDeleteRoleState] =
    useState<DeleteRoleState | null>(null);
  const [roleFilter, setRoleFilter] = useState("all");
  const [organizationFilter, setOrganizationFilter] = useState("all");
  const [authFilter, setAuthFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  // Mobile (<1024px) defaults to the card grid; desktop keeps the table and
  // remembers the user's choice. Mirrors the other list views.
  const [membersViewMode, setMembersViewMode] = useResponsiveViewMode({
    storageKey: "team-members_view",
  });
  const editingRoleId = editRole?.id;
  const errorToastIdsRef = useRef<Record<string, string | null>>({
    teamMembers: null,
    roles: null,
    permissions: null,
    rolePermissions: null,
  });

  const organizationsQuery = useOrganizations({
    enabled: isSuperAdmin && !isLoadingAuth,
  });

  const organizationOptions = useMemo(
    () =>
      (organizationsQuery.data ?? []).map((t) => ({
        value: getOrganizationIdValue(t),
        label: t.name,
      })),
    [organizationsQuery.data],
  );

  const usersQuery = useListUsers({
    organizationScoped,
    enabled: canSeeMembers && !isLoadingAuth,
  });
  const rolesQuery = useListRoles({
    enabled: canSeeRoles && !isLoadingAuth,
    organizationScoped,
  });
  const permissionsQuery = useListPermissions({
    enabled: canSeeRoles && !isLoadingAuth,
  });
  const rolePermissionsQuery = useGetRolePermissions(editRole?.id, {
    enabled: canSeeRoles && Boolean(editRole),
  });
  // Saving replaces the stored direct grants, so every edit starts from a
  // fresh read: gcTime 0 drops the cached set as soon as the dialog closes.
  const directGrantsQuery = useGetUserPermissions(editUser?.id, {
    enabled: Boolean(editUser),
    gcTime: 0,
  });

  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const deleteUserMutation = useDeleteUser();
  const disableUser = useDisableUser();
  const assignUserRoles = useAssignUserRoles();
  const updateUserPermissions = useUpdateUserPermissions();
  const createRole = useCreateRole();
  const updateRolePermissions = useUpdateRolePermissions();
  const deleteRole = useDeleteRole();

  const usersErrorMessage = usersQuery.error
    ? getApiErrorMessage(usersQuery.error, "Failed to load team members")
    : null;
  const rolesErrorMessage = rolesQuery.error
    ? getApiErrorMessage(rolesQuery.error, "Failed to load roles")
    : null;
  const permissionsErrorMessage = permissionsQuery.error
    ? getApiErrorMessage(
        permissionsQuery.error,
        "Failed to load permissions catalogue",
      )
    : null;
  const rolePermissionsErrorMessage = rolePermissionsQuery.error
    ? getApiErrorMessage(
        rolePermissionsQuery.error,
        "Failed to load permissions for this role",
      )
    : null;

  useEffect(() => {
    const toastTargets = [
      {
        key: "teamMembers",
        id: "team-members-load-error",
        message: canSeeMembers ? usersErrorMessage : null,
      },
      {
        key: "roles",
        id: "roles-load-error",
        message: canSeeRoles ? rolesErrorMessage : null,
      },
      {
        key: "permissions",
        id: "permissions-load-error",
        message: canSeeRoles ? permissionsErrorMessage : null,
      },
      {
        key: "rolePermissions",
        id: "role-permissions-load-error",
        message: Boolean(editRole) ? rolePermissionsErrorMessage : null,
      },
    ] as const;

    toastTargets.forEach(({ key, id, message }) => {
      if (!message) {
        errorToastIdsRef.current[key] = null;
        return;
      }

      if (errorToastIdsRef.current[key] === message) {
        return;
      }

      errorToastIdsRef.current[key] = message;
      toast.error(message, { id });
    });
  }, [
    canSeeMembers,
    canSeeRoles,
    editRole,
    editUser,
    permissionsErrorMessage,
    rolePermissionsErrorMessage,
    rolesErrorMessage,
    usersErrorMessage,
  ]);

  useEffect(() => {
    if (!canSeeMembers && canSeeRoles) {
      setActiveTab("roles");
    }
  }, [canSeeMembers, canSeeRoles]);

  useEffect(() => {
    if (!editingRoleId || !rolePermissionsQuery.data) return;

    const nextPermissionNames = rolePermissionsQuery.data.map(
      (permission) => permission.name,
    );

    setEditRole((current) =>
      current && current.id === editingRoleId
        ? areStringArraysEqual(current.permissionNames, nextPermissionNames)
          ? current
          : {
              ...current,
              permissionNames: nextPermissionNames,
            }
        : current,
    );
  }, [editingRoleId, rolePermissionsQuery.data]);

  const roleOptions = useMemo(
    () =>
      (rolesQuery.data ?? []).map((role) => ({
        value: String(role.id),
        label: formatRoleName(role.name),
      })),
    [rolesQuery.data],
  );

  // Role ids that map to the platform SUPER_ADMIN role. Used to relax the mandatory
  // Organization field when a super admin is creating another super admin.
  const superAdminRoleIds = useMemo(
    () =>
      (rolesQuery.data ?? [])
        .filter((role) => role.name === "SUPER_ADMIN")
        .map((role) => String(role.id)),
    [rolesQuery.data],
  );

  const permissionOptions = useMemo(
    () =>
      (permissionsQuery.data ?? []).map((permission) => ({
        value: permission.name,
        label: permission.description || permission.name,
      })),
    [permissionsQuery.data],
  );

  const rolePermissionsById = useMemo(
    () =>
      new Map(
        (rolesQuery.data ?? []).map((role) => [
          String(role.id),
          role.permissions ?? [],
        ]),
      ),
    [rolesQuery.data],
  );

  const handleCreate = async (values: InviteUserValues) => {
    try {
      await createUser.mutateAsync({
        username: values.username,
        email: values.email,
        password: values.password,
        displayName: values.displayName || undefined,
        roleIds: values.roleIds
          .map((roleId) => Number(roleId))
          .filter((roleId) => Number.isFinite(roleId)),
        organizationId: isSuperAdmin
          ? // An id that is not a number becomes null rather than NaN.
            Number(values.organizationId) || null
          : undefined,
      });
      setIsInviteOpen(false);
      toast.success("Member added successfully");
    } catch (error) {
      const detail = getApiErrorMessage(error, "");
      toast.error(`Failed to add member${detail ? `: ${detail}` : ""}`);
    }
  };

  const directGrants: DirectGrantsState = directGrantsQuery.data
    ? {
        status: "ready",
        permissionNames: directGrantsQuery.data.map(
          (permission) => permission.name,
        ),
      }
    : directGrantsQuery.isError
      ? { status: "unavailable" }
      : { status: "loading" };

  const handleUpdate = async (values: EditUserValues) => {
    if (!editUser || accessSaveBlockedReason) return;
    if (isSameUser({ id: editUser.id, email: values.email }, user)) {
      toast.error(
        "You cannot edit your own organization membership from this screen",
      );
      return;
    }
    const target = editUser;
    const changes = planMemberAccessChanges(
      {
        roleIds: target.roleIds,
        directPermissionNames:
          directGrants.status === "ready" ? directGrants.permissionNames : null,
      },
      values,
      rolePermissionsById,
    );
    const result = await saveMemberEdit(changes, {
      updateProfile: () =>
        updateUser.mutateAsync({
          id: target.id,
          payload: {
            email: values.email.trim(),
            username: values.username.trim() || undefined,
            displayName: values.displayName.trim() || undefined,
            active: target.active,
          },
          organizationScoped,
        }),
      assignRoles: (roleIds) =>
        assignUserRoles.mutateAsync({ id: target.id, roleIds }),
      setDirectGrants: (permissionNames) =>
        updateUserPermissions.mutateAsync({ id: target.id, permissionNames }),
    });

    if (result.ok) {
      setEditUser(null);
      toast.success("Member updated");
      return;
    }
    if (result.savedSteps.includes("roles")) {
      setEditUser((current) =>
        current?.id === target.id
          ? { ...current, roleIds: values.roleIds }
          : current,
      );
    }
    toast.error(
      describeMemberSaveFailure(result, getApiErrorMessage(result.error, "")),
    );
  };

  const handleDelete = async () => {
    if (!deleteUser) return;
    if (isSameUser(deleteUser, user)) {
      toast.error("You cannot remove yourself from this organization");
      return;
    }
    try {
      await deleteUserMutation.mutateAsync({
        id: deleteUser.id,
        organizationScoped,
      });
      setDeleteUser(null);
      toast.success("Member removed");
    } catch (error) {
      const detail = getApiErrorMessage(error, "");
      toast.error(`Failed to remove member${detail ? `: ${detail}` : ""}`);
    }
  };

  const handleResetMfa = async (target: UserDto) => {
    if (isSameUser(target, user)) {
      toast.error(
        "Turn off your own two-factor authentication from Your account.",
      );
      return;
    }
    if (
      !window.confirm(
        `Reset two-factor authentication for ${target.displayName || target.username || target.email}? ` +
          "They will sign in with their password only until they enroll again.",
      )
    ) {
      return;
    }
    try {
      const result = await resetMemberMfa(target.id);
      toast.success(result.message);
    } catch (error) {
      toast.error(
        getApiErrorMessage(error, "Could not reset two-factor authentication."),
      );
    }
  };

  const handleDisable = async (target: UserDto) => {
    if (isSameUser(target, user)) {
      toast.error(
        "You cannot change your own organization membership from this screen",
      );
      return;
    }
    const isCurrentlyActive = target.active !== false;
    if (!isCurrentlyActive && accessSaveBlockedReason) return;
    try {
      if (isCurrentlyActive) {
        await disableUser.mutateAsync({ id: target.id, organizationScoped });
        toast.success("Member disabled");
      } else {
        // Re-enabling restores the member exactly as disabled: disabling never
        // touches roles, so neither does this. Re-sending them would rebuild
        // the set from the roles list, which may be unloaded or failed.
        await updateUser.mutateAsync({
          id: target.id,
          payload: {
            email: target.email,
            username: target.username,
            displayName: target.displayName,
            authMethod: target.authMethod,
            mustChangePassword: target.mustChangePassword ?? false,
            active: true,
            enabled: true,
          },
          organizationScoped,
        });
        toast.success("Member enabled");
      }
    } catch (error) {
      const detail = getApiErrorMessage(error, "");
      toast.error(
        isCurrentlyActive
          ? `Failed to disable member${detail ? `: ${detail}` : ""}`
          : `Failed to enable member${detail ? `: ${detail}` : ""}`,
      );
    }
  };

  const handleCreateRole = async () => {
    if (!createRoleForm.name.trim()) {
      toast.error("Role name is required");
      return;
    }

    try {
      await createRole.mutateAsync({
        name: createRoleForm.name.trim(),
        description: createRoleForm.description.trim() || undefined,
        permissionNames: createRoleForm.permissionNames,
        organizationId: organizationScoped
          ? Number(user?.organizationId) || null
          : null,
      });
      setCreateRoleForm(EMPTY_CREATE_ROLE_FORM);
      setIsCreateRoleOpen(false);
      toast.success("Role created");
    } catch (error) {
      const detail = getApiErrorMessage(error, "");
      toast.error(`Failed to create role${detail ? `: ${detail}` : ""}`);
    }
  };

  const handleSaveRole = async () => {
    if (!editRole || accessSaveBlockedReason) return;

    try {
      await updateRolePermissions.mutateAsync({
        id: editRole.id,
        permissionNames: editRole.permissionNames,
      });
      setEditRole(null);
      toast.success("Role permissions updated");
    } catch (error) {
      const detail = getApiErrorMessage(error, "");
      toast.error(
        `Failed to update role permissions${detail ? `: ${detail}` : ""}`,
      );
    }
  };

  const handleDeleteRole = async () => {
    if (!deleteRoleState) return;

    try {
      await deleteRole.mutateAsync(deleteRoleState.id);
      setDeleteRoleState(null);
      toast.success("Role deleted");
    } catch (error) {
      const detail = getApiErrorMessage(error, "");
      toast.error(`Failed to delete role${detail ? `: ${detail}` : ""}`);
    }
  };

  const availableRoles = useMemo(() => {
    const roles = new Set<string>();
    (usersQuery.data ?? []).forEach((u) =>
      u.roles?.forEach((r) => roles.add(r)),
    );
    return Array.from(roles).sort();
  }, [usersQuery.data]);

  const filteredUsers = useMemo(() => {
    let users = usersQuery.data ?? [];
    if (isSuperAdmin && organizationFilter !== "all") {
      const selectedOrganization = organizationOptions.find(
        (organization) => organization.value === organizationFilter,
      );
      users = users.filter(
        (u) =>
          String(u.organizationId ?? "") === organizationFilter ||
          Boolean(
            selectedOrganization?.label &&
            u.organizationName === selectedOrganization.label,
          ),
      );
    }
    if (roleFilter !== "all") {
      users = users.filter((u) => u.roles?.includes(roleFilter));
    }
    if (authFilter !== "all") {
      users = users.filter((u) => (u.authMethod ?? "LOCAL") === authFilter);
    }
    if (statusFilter !== "all") {
      users = users.filter((u) =>
        statusFilter === "active" ? u.active !== false : u.active === false,
      );
    }
    return [...users].sort((a, b) => {
      const aIsCurrent = isSameUser(a, user);
      const bIsCurrent = isSameUser(b, user);
      if (aIsCurrent === bIsCurrent) return 0;
      return aIsCurrent ? -1 : 1;
    });
  }, [
    usersQuery.data,
    isSuperAdmin,
    organizationFilter,
    organizationOptions,
    roleFilter,
    authFilter,
    statusFilter,
    user,
  ]);

  const hasMemberFilters =
    (isSuperAdmin && organizationFilter !== "all") ||
    roleFilter !== "all" ||
    authFilter !== "all" ||
    statusFilter !== "all";
  const resetMemberFilters = useCallback(() => {
    setOrganizationFilter("all");
    setRoleFilter("all");
    setAuthFilter("all");
    setStatusFilter("all");
  }, []);
  const organizationChipOptions = useMemo(
    () => [
      { label: "All organizations", value: "all" },
      ...organizationOptions,
    ],
    [organizationOptions],
  );
  const roleChipOptions = useMemo(
    () => [
      { label: "All roles", value: "all" },
      ...availableRoles.map((role) => ({
        label: formatRoleName(role),
        value: role,
      })),
    ],
    [availableRoles],
  );

  const usersById = useMemo(
    () =>
      new Map(
        (usersQuery.data ?? []).map((teamUser) => [
          String(teamUser.id),
          teamUser,
        ]),
      ),
    [usersQuery.data],
  );

  const editMember = (teamUser: UserDto) => {
    const latestUser = usersById.get(String(teamUser.id)) ?? teamUser;
    setEditUser(buildEditUserState(latestUser, rolesQuery.data));
  };
  const deleteMember = (teamUser: UserDto) =>
    setDeleteUser({
      id: teamUser.id,
      displayName: teamUser.displayName || teamUser.username || teamUser.email,
    });

  const columns = useMemo(
    () =>
      createUserColumns({
        canManage: canManageMembers,
        isSuperAdmin,
        currentUserId: user?.id,
        currentUserEmail: user?.email,
        enableBlockedReason: accessSaveBlockedReason,
        onEdit: editMember,
        onDisable: handleDisable,
        onDelete: deleteMember,
        onResetMfa: handleResetMfa,
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      accessSaveBlockedReason,
      canManageMembers,
      isSuperAdmin,
      rolesQuery.data,
      user?.email,
      user?.id,
      usersById,
    ],
  );

  const renderMemberGrid = (members: UserDto[]) =>
    members.length === 0 ? (
      <p className="rounded-xl border border-dashed border-border px-6 py-10 text-center text-sm text-muted-foreground">
        No team members found.
      </p>
    ) : (
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {members.map((teamUser) => (
          <MemberCard
            key={teamUser.id}
            user={teamUser}
            isSuperAdmin={isSuperAdmin}
            canManage={canManageMembers}
            isCurrentUser={isSameUser(teamUser, user)}
            enableBlockedReason={accessSaveBlockedReason}
            onEdit={editMember}
            onDisable={handleDisable}
            onDelete={deleteMember}
            onResetMfa={handleResetMfa}
          />
        ))}
      </div>
    );

  if (isLoadingAuth) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-80" />
        <Skeleton className="h-12 w-72" />
        <Skeleton className="h-112 w-full rounded-2xl" />
      </div>
    );
  }

  if (!canManage) {
    return (
      <Unauthorised description="You do not have permission to view member settings." />
    );
  }

  return (
    <div>
      <div className="mx-auto w-full space-y-6">
        <PageHeader
          level="section"
          title="Members & roles"
          subtitle="Manage members, roles, and permissions."
          actions={
            <>
              {canManageMembers ? (
                <InviteUserDialog
                  open={isInviteOpen}
                  canCreate={canManageMembers}
                  isSuperAdmin={isSuperAdmin}
                  superAdminRoleIds={superAdminRoleIds}
                  isPending={createUser.isPending}
                  roleOptions={roleOptions}
                  organizationOptions={organizationOptions}
                  rolesHelpText={
                    roleOptions.length === 0
                      ? canManageRoleDefs
                        ? "No roles are available yet. Create a role in the Roles tab before adding a member."
                        : "No assignable roles are available for this account."
                      : "Choose at least one role for the new member."
                  }
                  onOpenChange={setIsInviteOpen}
                  onCreate={handleCreate}
                />
              ) : null}
            </>
          }
        />

        <Tabs
          value={activeTab}
          onValueChange={setActiveTab}
          className="space-y-4"
        >
          {canSeeMembers && canSeeRoles ? (
            <TabsList>
              <TabsTrigger value="members">
                Members ({usersQuery.data?.length ?? 0})
              </TabsTrigger>
              <TabsTrigger value="roles">
                Roles ({rolesQuery.data?.length ?? 0})
              </TabsTrigger>
            </TabsList>
          ) : null}

          {canSeeMembers ? (
            <TabsContent value="members" className="space-y-4">
              <RoleDescriptions />
              <CustomTable
                viewSwitcher={{
                  value: membersViewMode,
                  onValueChange: setMembersViewMode,
                }}
                renderGrid={renderMemberGrid}
                columns={columns}
                data={filteredUsers}
                isLoading={usersQuery.isLoading}
                loadingRowCount={6}
                searchBy={MEMBER_SEARCH_KEYS}
                searchPlaceholder="Search members..."
                emptyTableMsg="No team members found."
                showColumnVisibility={false}
                getRowId={getMemberRowId}
                tableElementClassName="table-fixed"
                toolbarFilters={
                  <>
                    {isSuperAdmin ? (
                      <FilterSelectChip
                        label="Organization"
                        value={organizationFilter}
                        onValueChange={setOrganizationFilter}
                        disabled={organizationsQuery.isLoading}
                        options={organizationChipOptions}
                      />
                    ) : null}
                    <FilterSelectChip
                      label="Role"
                      value={roleFilter}
                      onValueChange={setRoleFilter}
                      options={roleChipOptions}
                    />
                    <FilterSelectChip
                      label="Sign-in"
                      value={authFilter}
                      onValueChange={setAuthFilter}
                      options={AUTH_FILTER_OPTIONS}
                    />
                    <FilterSelectChip
                      label="Status"
                      value={statusFilter}
                      onValueChange={setStatusFilter}
                      options={STATUS_FILTER_OPTIONS}
                    />
                    {hasMemberFilters ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 text-muted-foreground"
                        onClick={resetMemberFilters}
                      >
                        Reset
                      </Button>
                    ) : null}
                  </>
                }
              />
            </TabsContent>
          ) : null}

          {canSeeRoles ? (
            <TabsContent value="roles">
              <RolesPanel
                canManageRoles={canManageRoleDefs}
                canDeleteRoles={canDeleteRoleDefs}
                canViewRoles={canViewRoleDefs}
                roles={rolesQuery.data ?? []}
                permissionOptions={permissionOptions}
                isLoading={rolesQuery.isLoading || permissionsQuery.isLoading}
                createRoleState={createRoleForm}
                editRoleState={editRole}
                deleteRoleState={deleteRoleState}
                isCreateOpen={isCreateRoleOpen}
                isCreatePending={createRole.isPending}
                isUpdatePending={updateRolePermissions.isPending}
                isDeletePending={deleteRole.isPending}
                isRolePermissionsLoading={rolePermissionsQuery.isLoading}
                saveBlockedReason={accessSaveBlockedReason}
                onCreateOpenChange={setIsCreateRoleOpen}
                onCreateRoleChange={setCreateRoleForm}
                onEditRoleChange={setEditRole}
                onEditRoleOpenChange={(open) => {
                  if (!open) setEditRole(null);
                }}
                onDeleteRoleOpenChange={(open) => {
                  if (!open) setDeleteRoleState(null);
                }}
                onCreateRole={handleCreateRole}
                onSaveRole={handleSaveRole}
                onDeleteRole={handleDeleteRole}
                onStartEditRole={(role) =>
                  setEditRole({
                    id: role.id,
                    name: role.name,
                    description: role.description ?? "",
                    permissionNames: (role.permissions ?? []).slice(),
                  })
                }
                onStartDeleteRole={(role) =>
                  setDeleteRoleState({
                    id: role.id,
                    name: role.name,
                  })
                }
              />
            </TabsContent>
          ) : null}
        </Tabs>
      </div>

      <EditUserDialog
        open={Boolean(editUser)}
        user={editUser}
        isPending={
          updateUser.isPending ||
          assignUserRoles.isPending ||
          updateUserPermissions.isPending
        }
        directGrants={
          rolesQuery.isLoading ? { status: "loading" } : directGrants
        }
        roleOptions={roleOptions}
        rolePermissionsById={rolePermissionsById}
        permissionOptions={permissionOptions}
        saveBlockedReason={accessSaveBlockedReason}
        onOpenChange={(open) => {
          if (!open) setEditUser(null);
        }}
        onSave={handleUpdate}
      />

      <DeleteUserDialog
        open={Boolean(deleteUser)}
        user={deleteUser}
        isPending={deleteUserMutation.isPending}
        onOpenChange={(open) => {
          if (!open) setDeleteUser(null);
        }}
        onDelete={handleDelete}
      />
    </div>
  );
}
