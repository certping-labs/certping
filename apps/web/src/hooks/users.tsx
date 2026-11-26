// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  addUserPermissions,
  assignUserRoles,
  createRole,
  createUser,
  deleteRole,
  deleteUser,
  disableUser,
  getRoleById,
  getRolePermissions,
  getUserById,
  getUserPermissions,
  listPermissions,
  listPermissionsByResource,
  listRoles,
  listUsers,
  removeUserPermissions,
  updateRolePermissions,
  updateUser,
  updateUserPermissions,
} from "@/lib/backend/users";
import { getApiErrorMessage } from "@/lib/backend/common";
import type {
  CreateRoleRequest,
  CreateUserRequest,
  UpdateUserRequest,
} from "@/types/auth";
import {
  invalidateAuditQueries,
  invalidateTeamQueries,
} from "./query-invalidation";

export { getApiErrorMessage } from "@/lib/backend/common";

export const USERS_QUERY_KEY = "users";
export const ROLES_QUERY_KEY = "roles";
export const PERMISSIONS_QUERY_KEY = "permissions";

// ---- Users ----

export const useGetUser = (
  id: number | string | undefined,
  options?: { enabled?: boolean },
) =>
  useQuery({
    queryKey: [USERS_QUERY_KEY, id],
    enabled: options?.enabled !== false && id !== undefined,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => getUserById(id!),
  });

export const useListUsers = (options?: {
  organizationScoped?: boolean;
  enabled?: boolean;
}) =>
  useQuery({
    queryKey: [USERS_QUERY_KEY, options?.organizationScoped ?? false],
    enabled: options?.enabled !== false,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => listUsers(options?.organizationScoped),
  });

export const useCreateUser = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: (payload: CreateUserRequest) => createUser(payload),
    onSuccess: async () => {
      await Promise.all([
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to create user"));
    },
  });
};

export const useUpdateUser = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: ({
      id,
      payload,
      organizationScoped,
    }: {
      id: number | string;
      payload: UpdateUserRequest;
      organizationScoped?: boolean;
    }) => updateUser(id, payload, organizationScoped),
    onSuccess: async () => {
      await Promise.all([
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to update user"));
    },
  });
};

export const useDeleteUser = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: ({
      id,
      organizationScoped,
    }: {
      id: number | string;
      organizationScoped?: boolean;
    }) => deleteUser(id, organizationScoped),
    onSuccess: async () => {
      await Promise.all([
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to delete user"));
    },
  });
};

export const useDisableUser = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: ({
      id,
      organizationScoped,
    }: {
      id: number | string;
      organizationScoped?: boolean;
    }) => disableUser(id, organizationScoped),
    onSuccess: async () => {
      await Promise.all([
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to disable user"));
    },
  });
};

export const useGetUserPermissions = (
  id: number | string | undefined,
  options?: { enabled?: boolean; gcTime?: number },
) =>
  useQuery({
    queryKey: [USERS_QUERY_KEY, id, "permissions"],
    enabled: options?.enabled !== false && id !== undefined,
    gcTime: options?.gcTime,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => getUserPermissions(id!),
  });

export const useUpdateUserPermissions = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: ({
      id,
      permissionNames,
    }: {
      id: number | string;
      permissionNames: string[];
    }) => updateUserPermissions(id, permissionNames),
    onSuccess: async (_, { id }) => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: [USERS_QUERY_KEY, id, "permissions"],
        }),
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to update permissions"));
    },
  });
};

export const useAddUserPermissions = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: ({
      id,
      permissionNames,
    }: {
      id: number | string;
      permissionNames: string[];
    }) => addUserPermissions(id, permissionNames),
    onSuccess: async (_, { id }) => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: [USERS_QUERY_KEY, id, "permissions"],
        }),
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to add permissions"));
    },
  });
};

export const useRemoveUserPermissions = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: ({
      id,
      permissionNames,
    }: {
      id: number | string;
      permissionNames: string[];
    }) => removeUserPermissions(id, permissionNames),
    onSuccess: async (_, { id }) => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: [USERS_QUERY_KEY, id, "permissions"],
        }),
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to remove permissions"));
    },
  });
};

export const useAssignUserRoles = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: ({ id, roleIds }: { id: number | string; roleIds: number[] }) =>
      assignUserRoles(id, roleIds),
    onSuccess: async () => {
      await Promise.all([
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to assign roles"));
    },
  });
};

// ---- Roles ----

export const useGetRole = (
  id: number | string | undefined,
  options?: { enabled?: boolean },
) =>
  useQuery({
    queryKey: [ROLES_QUERY_KEY, id],
    enabled: options?.enabled !== false && id !== undefined,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => getRoleById(id!),
  });

export const useGetRolePermissions = (
  id: number | string | undefined,
  options?: { enabled?: boolean },
) =>
  useQuery({
    queryKey: [ROLES_QUERY_KEY, id, "permissions"],
    enabled: options?.enabled !== false && id !== undefined,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => getRolePermissions(id!),
  });

export const useListRoles = (options?: {
  enabled?: boolean;
  organizationScoped?: boolean;
}) =>
  useQuery({
    queryKey: [ROLES_QUERY_KEY, options?.organizationScoped ?? false],
    enabled: options?.enabled !== false,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => listRoles(),
  });

export const useCreateRole = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: (payload: CreateRoleRequest) => createRole(payload),
    onSuccess: async () => {
      await Promise.all([
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to create role"));
    },
  });
};

export const useUpdateRolePermissions = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: ({
      id,
      permissionNames,
    }: {
      id: number | string;
      permissionNames: string[];
    }) => updateRolePermissions(id, permissionNames),
    onSuccess: async (_, { id }) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: [ROLES_QUERY_KEY, id] }),
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(
        getApiErrorMessage(error, "Failed to update role permissions"),
      );
    },
  });
};

export const useDeleteRole = () => {
  const queryClient = useQueryClient();

  return useMutation({
    retry: false,
    mutationFn: (id: number | string) => deleteRole(id),
    onSuccess: async () => {
      await Promise.all([
        invalidateTeamQueries(queryClient),
        invalidateAuditQueries(queryClient),
      ]);
    },
    onError: (error) => {
      console.error(getApiErrorMessage(error, "Failed to delete role"));
    },
  });
};

// ---- Permissions ----

export const useListPermissionsByResource = (
  resource: string | undefined,
  options?: { enabled?: boolean },
) =>
  useQuery({
    queryKey: [PERMISSIONS_QUERY_KEY, resource],
    enabled: options?.enabled !== false && Boolean(resource),
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: () => listPermissionsByResource(resource!),
  });

export const useListPermissions = (options?: { enabled?: boolean }) =>
  useQuery({
    queryKey: [PERMISSIONS_QUERY_KEY],
    enabled: options?.enabled !== false,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: listPermissions,
  });
