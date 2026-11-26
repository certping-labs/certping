// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes, publicApiClient } from "@/lib/api";
import type {
  AdminSetupRequest,
  AuthSession,
  AuthTokenClaims,
  AuthTokenResponse,
  CurrentUserResponse,
  SsoUser,
  UnifiedLoginRequest,
} from "@/types/auth";
import { decodeJWT } from "@/lib/utils";

const DEFAULT_SESSION_TTL_SECONDS = 3600;

const toExpiresInMs = (expiresIn?: number): number => {
  if (!Number.isFinite(expiresIn) || (expiresIn ?? 0) <= 0) {
    return DEFAULT_SESSION_TTL_SECONDS * 1000;
  }

  return expiresIn! > 100_000 ? expiresIn! : expiresIn! * 1000;
};

const toUser = (
  payload: CurrentUserResponse | AuthTokenResponse,
  fallback?: CurrentUserResponse | AuthTokenResponse,
  claims?: AuthTokenClaims | null,
): SsoUser => ({
  id:
    payload.userId != null
      ? String(payload.userId)
      : payload.email || fallback?.email || "unknown-user",
  email: payload.email || fallback?.email || "",
  organizationId: payload.organizationId ?? fallback?.organizationId ?? null,
  organizationName:
    payload.organizationName ?? fallback?.organizationName ?? null,
  roles: Array.isArray(payload.roles) ? payload.roles : [],
  permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
  authMethod:
    payload.authMethod ?? fallback?.authMethod ?? claims?.authMethod ?? null,
  mustChangePassword:
    payload.mustChangePassword ??
    fallback?.mustChangePassword ??
    claims?.mustChangePassword ??
    false,
});

export const mergeUserWithClaims = (
  user: SsoUser,
  claims?: AuthTokenClaims | null,
): SsoUser => {
  if (!claims) {
    return user;
  }

  return {
    ...user,
    email: claims.sub ?? user.email,
    id: claims.userId != null ? String(claims.userId) : user.id,
    organizationId: claims.organizationId ?? user.organizationId ?? null,
    organizationName: claims.organizationName ?? user.organizationName ?? null,
    roles:
      Array.isArray(claims.roles) && claims.roles.length > 0
        ? claims.roles
        : user.roles,
    permissions: Array.isArray(claims.permissions)
      ? claims.permissions
      : user.permissions,
    authMethod: claims.authMethod ?? user.authMethod ?? null,
    mustChangePassword: claims.mustChangePassword ?? user.mustChangePassword,
  };
};

const isSuperAdmin = (user: SsoUser): boolean =>
  user.roles.includes("SUPER_ADMIN");

export const normalizeAuthSession = (
  payload: AuthTokenResponse,
  currentUser?: CurrentUserResponse,
): AuthSession => {
  const accessToken = (payload.accessToken ?? payload.token)?.trim();
  const refreshToken = payload.refreshToken?.trim();

  if (!accessToken || !refreshToken) {
    throw new Error("Authentication response did not include tokens.");
  }

  const claims = decodeJWT<AuthTokenClaims>(accessToken);
  const authMethod =
    payload.authMethod ?? currentUser?.authMethod ?? claims?.authMethod ?? null;
  const baseUser = currentUser
    ? toUser({ ...currentUser, authMethod }, payload, claims)
    : toUser({ ...payload, authMethod }, undefined, claims);
  const user = mergeUserWithClaims(baseUser, claims);

  return {
    user,
    accessToken,
    refreshToken,
    expiresAt: Date.now() + toExpiresInMs(payload.expiresIn),
    tokenType: payload.tokenType || "Bearer",
    isSuperAdmin: isSuperAdmin(user),
  };
};

export const setupAdmin = async (
  payload: AdminSetupRequest,
): Promise<AuthTokenResponse> => {
  const response = await publicApiClient.post<AuthTokenResponse>(
    apiRoutes.mutation.admin.setup,
    payload,
  );
  return {
    ...response.data,
    authMethod: response.data.authMethod ?? "LOCAL",
  };
};

export const loginUser = async (
  payload: UnifiedLoginRequest,
): Promise<AuthTokenResponse> => {
  const response = await publicApiClient.post<AuthTokenResponse>(
    apiRoutes.mutation.auth.login,
    payload,
  );
  return {
    ...response.data,
    authMethod: response.data.authMethod ?? "LOCAL",
  };
};

/**
 * Finishes single sign-on: the server's redirect carries a one-time `code`, never tokens, and
 * this trades it for the same response a password login returns. The code is single use.
 */
export const exchangeSsoCode = async (
  code: string,
): Promise<AuthTokenResponse> => {
  const response = await publicApiClient.post<AuthTokenResponse>(
    apiRoutes.mutation.auth.ssoExchange,
    { code },
  );
  return {
    ...response.data,
    authMethod: response.data.authMethod ?? "SSO",
  };
};

/** Public: whether the first Platform Super Admin still has to be created. */
export async function getSetupStatus(): Promise<{ setupRequired: boolean }> {
  const response = await publicApiClient.get<{ setupRequired: boolean }>(
    apiRoutes.query.auth.setupStatus,
  );
  return response.data;
}

export interface FirstRunSetupRequest {
  username: string;
  email: string;
  password: string;
  displayName?: string;
}

/** First run only: creates the first Platform Super Admin; 409 once any user exists. */
export async function completeFirstRunSetup(
  payload: FirstRunSetupRequest,
): Promise<{ message?: string; username: string; email: string }> {
  const response = await publicApiClient.post<{
    message?: string;
    username: string;
    email: string;
  }>(apiRoutes.mutation.auth.setup, payload);
  return response.data;
}

export async function requestPasswordReset(payload: {
  email: string;
}): Promise<{ message?: string }> {
  const response = await publicApiClient.post<{ message?: string }>(
    apiRoutes.mutation.auth.forgotPassword,
    payload,
  );
  return response.data;
}

export async function resetPasswordWithToken(
  token: string,
  payload: { newPassword: string; confirmPassword: string },
): Promise<{ message?: string }> {
  const response = await publicApiClient.put<{ message?: string }>(
    apiRoutes.mutation.auth.resetPassword(token),
    payload,
  );
  return response.data;
}

export const refreshSession = async (): Promise<AuthTokenResponse> => {
  const refreshedSession = await apiClient.refreshAuthSession();
  if (!refreshedSession) {
    throw new Error("Refresh token missing.");
  }
  return refreshedSession;
};

export const getCurrentUser = async (
  accessToken: string,
): Promise<CurrentUserResponse> => {
  const response = await publicApiClient.get<CurrentUserResponse>(
    apiRoutes.query.auth.currentUser,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );

  return response.data;
};

export const logoutSession = async (
  accessToken: string,
  refreshToken: string,
): Promise<void> => {
  await publicApiClient.post(
    apiRoutes.mutation.auth.logout,
    { refreshToken },
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );
};

/** Finishes a sign-in that answered mfaRequired: the challenge plus an authenticator or recovery code. */
export const loginWithMfa = async (payload: {
  mfaToken: string;
  code: string;
}): Promise<AuthTokenResponse> => {
  const response = await publicApiClient.post<AuthTokenResponse>(
    apiRoutes.mutation.auth.loginMfa,
    payload,
  );
  return {
    ...response.data,
    authMethod: response.data.authMethod ?? "LOCAL",
  };
};

export interface MfaStatus {
  enabled: boolean;
  confirmedAt: string | null;
  recoveryCodesRemaining: number;
}

export interface MfaEnrollment {
  /** Base32 secret to type into an authenticator app. */
  secret: string;
  otpauthUri: string;
}

export const getMfaStatus = async (): Promise<MfaStatus> => {
  const response = await apiClient.get<MfaStatus>(apiRoutes.query.auth.mfa);
  return response.data;
};

export const startMfaEnrollment = async (): Promise<MfaEnrollment> => {
  const response = await apiClient.post<MfaEnrollment>(
    apiRoutes.mutation.auth.mfaEnroll,
  );
  return response.data;
};

/** Confirms the enrollment with a code; the recovery codes come back once. */
export const confirmMfaEnrollment = async (payload: {
  code: string;
}): Promise<{ message: string; recoveryCodes: string[] }> => {
  const response = await apiClient.post<{
    message: string;
    recoveryCodes: string[];
  }>(apiRoutes.mutation.auth.mfaConfirm, payload);
  return response.data;
};

export const disableMfa = async (payload: {
  password: string;
}): Promise<void> => {
  await apiClient.delete(apiRoutes.mutation.auth.mfaDisable, { data: payload });
};

/** users:manage: clears a member's second factor so they can sign in and enroll again. */
export const resetMemberMfa = async (
  userId: number | string,
): Promise<{ message: string }> => {
  const response = await apiClient.delete<{ message: string }>(
    apiRoutes.mutation.auth.mfaReset(userId),
  );
  return response.data;
};

export const changePassword = async (payload: {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}): Promise<void> => {
  await apiClient.post(apiRoutes.mutation.auth.changePassword, payload);
};
