// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export type AuthMethod = "LOCAL" | "SSO";
export interface AuthTokenClaims {
  sub?: string;
  userId?: string | number;
  organizationId?: string | null;
  organizationName?: string | null;
  roles?: string[];
  permissions?: string[];
  authMethod?: AuthMethod | null;
  mustChangePassword?: boolean;
}

// Root login request/response
export interface RootLoginRequest {
  username: string;
  password: string;
}

export interface UnifiedLoginRequest {
  identifier: string;
  password: string;
}

export interface AdminSetupRequest {
  username: string;
  password: string;
  email: string;
  displayName: string;
}

export interface RootLoginResponse {
  token?: string;
  accessToken?: string;
  refreshToken?: string;
  tokenType?: string;
  expiresIn?: number;
  username?: string;
  email?: string;
  organizationId?: string;
  organizationName?: string;
  userId?: string | number;
  roles?: string[];
  permissions?: string[];
  authMethod?: AuthMethod | null;
  mustChangePassword?: boolean;
  message?: string;
}

export interface AuthTokenResponse {
  token?: string;
  accessToken?: string;
  refreshToken?: string;
  tokenType?: string;
  expiresIn?: number;
  userId?: string | number;
  username?: string;
  email: string;
  organizationId?: string | null;
  organizationName?: string | null;
  roles: string[];
  permissions: string[];
  authMethod?: AuthMethod | null;
  mustChangePassword?: boolean;
  message?: string;
  /** The password was right but a one-time code is needed; no tokens were issued. */
  mfaRequired?: boolean;
  /** The challenge to send with the code, good for five minutes. */
  mfaToken?: string;
}

export interface CurrentUserResponse {
  email: string;
  userId?: string | number;
  organizationId?: string | null;
  organizationName?: string | null;
  roles: string[];
  permissions: string[];
  authMethod?: AuthMethod | null;
  mustChangePassword?: boolean;
}

export interface MessageResponse {
  success?: boolean;
  message?: string;
}

// JWT token claims from SSO auth
export interface SsoUser {
  id: string;
  email: string;
  organizationId: string | null;
  organizationName: string | null;
  roles: string[];
  permissions: string[];
  authMethod?: AuthMethod | null;
  mustChangePassword?: boolean;
}

export interface AuthSession {
  user: SsoUser;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  tokenType: string;
  isSuperAdmin: boolean;
}

export interface Organization {
  id: number;
  name: string;
  slug?: string;
  domain?: string;
  active?: boolean;
  agentHeartbeatCadenceMinutes?: number;
  softDeleteRetentionDays?: number;
  oidcEnabled?: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface SsoTokenResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  userId: string;
  email: string;
  organizationId?: string;
  organizationName?: string;
  roles: string[];
  permissions: string[];
  authMethod?: AuthMethod | null;
}

// ---- Users ----

export interface UserDto {
  id: number | string;
  email: string;
  username?: string;
  displayName?: string;
  organizationId?: number | null;
  organizationName?: string | null;
  authMethod?: AuthMethod;
  mustChangePassword?: boolean;
  roles?: string[];
  permissions?: string[];
  active?: boolean;
  enabled?: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface CreateUserRequest {
  username: string;
  password: string;
  email: string;
  displayName?: string;
  roleIds?: number[];
  organizationId?: number | null;
}

export interface UpdateUserRequest {
  email: string;
  username?: string;
  displayName?: string;
  authMethod?: AuthMethod;
  mustChangePassword?: boolean;
  roles?: string[];
  active?: boolean;
  enabled?: boolean;
}

// ---- Roles ----

export interface RoleDto {
  id: number;
  name: string;
  description?: string;
  organizationId?: number | null;
  isSystemRole?: boolean;
  permissions?: string[];
  createdAt?: string;
  updatedAt?: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permissionNames?: string[];
  organizationId?: number | null;
}

// ---- Permissions ----

export interface PermissionDto {
  id: number;
  name: string;
  resource?: string;
  action?: string;
  description?: string;
}
