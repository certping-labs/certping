// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import type {
  CreateRoleRequest,
  CreateUserRequest,
  PermissionDto,
  RoleDto,
  UpdateUserRequest,
  UserDto,
} from "@/types/auth";

interface UserApiDto extends Omit<UserDto, "id"> {
  id: number;
}

// ---- Users ----

export const getUserById = async (id: number | string): Promise<UserDto> => {
  const response = await apiClient.get<UserApiDto>(
    apiRoutes.query.users.detail(id),
  );
  return response.data;
};

export const listUsers = async (
  organizationScoped = false,
): Promise<UserDto[]> => {
  const url = organizationScoped
    ? apiRoutes.query.users.organizationList
    : apiRoutes.query.users.list;
  const response = await apiClient.get<UserApiDto[]>(url);
  return response.data;
};

export const createUser = async (
  payload: CreateUserRequest,
): Promise<UserDto> => {
  const response = await apiClient.post<UserApiDto>(
    apiRoutes.mutation.users.create,
    payload,
  );
  return response.data;
};

export const updateUser = async (
  id: number | string,
  payload: UpdateUserRequest,
  organizationScoped = false,
): Promise<UserDto> => {
  const url = organizationScoped
    ? apiRoutes.mutation.users.organizationUpdate(id)
    : apiRoutes.mutation.users.update(id);
  const response = await apiClient.put<UserApiDto>(url, payload);
  return response.data;
};

export const deleteUser = async (
  id: number | string,
  organizationScoped = false,
): Promise<void> => {
  const url = organizationScoped
    ? apiRoutes.mutation.users.organizationDelete(id)
    : apiRoutes.mutation.users.delete(id);
  await apiClient.delete(url);
};

export const disableUser = async (
  id: number | string,
  organizationScoped = false,
): Promise<void> => {
  const url = organizationScoped
    ? apiRoutes.mutation.users.organizationDisable(id)
    : apiRoutes.mutation.users.disable(id);
  await apiClient.post(url);
};

export const getUserPermissions = async (
  id: number | string,
): Promise<PermissionDto[]> => {
  const response = await apiClient.get<PermissionDto[]>(
    apiRoutes.query.users.permissions(id),
  );
  return response.data;
};

export const updateUserPermissions = async (
  id: number | string,
  permissionNames: string[],
): Promise<PermissionDto[]> => {
  const response = await apiClient.put<PermissionDto[]>(
    apiRoutes.mutation.users.updatePermissions(id),
    { permissionNames },
  );
  return response.data;
};

export const addUserPermissions = async (
  id: number | string,
  permissionNames: string[],
): Promise<PermissionDto[]> => {
  const response = await apiClient.post<PermissionDto[]>(
    apiRoutes.mutation.users.updatePermissions(id),
    { permissionNames },
  );
  return response.data;
};

export const removeUserPermissions = async (
  id: number | string,
  permissionNames: string[],
): Promise<PermissionDto[]> => {
  const response = await apiClient.delete<PermissionDto[]>(
    apiRoutes.mutation.users.updatePermissions(id),
    { permissionNames },
  );
  return response.data;
};

export const assignUserRoles = async (
  id: number | string,
  roleIds: number[],
): Promise<void> => {
  await apiClient.put(apiRoutes.mutation.users.assignRoles(id), { roleIds });
};

// ---- Roles ----

export const listRoles = async (): Promise<RoleDto[]> => {
  const response = await apiClient.get<RoleDto[]>(apiRoutes.query.roles.list);
  return response.data;
};

export const createRole = async (
  payload: CreateRoleRequest,
): Promise<RoleDto> => {
  const response = await apiClient.post<RoleDto>(
    apiRoutes.mutation.roles.create,
    payload,
  );
  return response.data;
};

export const deleteRole = async (id: number | string): Promise<void> => {
  await apiClient.delete(apiRoutes.mutation.roles.delete(id));
};

export const getRoleById = async (id: number | string): Promise<RoleDto> => {
  const response = await apiClient.get<RoleDto>(
    apiRoutes.query.roles.detail(id),
  );
  return response.data;
};

export const getRolePermissions = async (
  id: number | string,
): Promise<PermissionDto[]> => {
  const response = await apiClient.get<PermissionDto[]>(
    apiRoutes.query.roles.permissions(id),
  );
  return response.data;
};

export const updateRolePermissions = async (
  id: number | string,
  permissionNames: string[],
): Promise<RoleDto> => {
  const response = await apiClient.put<RoleDto>(
    apiRoutes.mutation.roles.updatePermissions(id),
    { permissionNames },
  );
  return response.data;
};

// ---- Permissions ----

export const listPermissions = async (): Promise<PermissionDto[]> => {
  const response = await apiClient.get<PermissionDto[]>(
    apiRoutes.query.permissions.list,
  );
  return response.data;
};

export const listPermissionsByResource = async (
  resource: string,
): Promise<PermissionDto[]> => {
  const response = await apiClient.get<PermissionDto[]>(
    apiRoutes.query.permissions.byResource(resource),
  );
  return response.data;
};
