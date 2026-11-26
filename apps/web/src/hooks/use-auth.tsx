// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

import {
  getCurrentUser,
  mergeUserWithClaims,
  logoutSession,
  normalizeAuthSession,
  refreshSession,
} from "@/lib/backend/auth";
import type { AuthTokenClaims, AuthTokenResponse } from "@/types/auth";
import {
  tokenStorage,
  useAuthStore,
  useAuthStoreHydrated,
} from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { decodeJWT } from "@/lib/utils";
import { usePageRestore } from "@/hooks/use-page-restore";

let authBootstrapPromise: Promise<void> | null = null;
let authBootstrapKey: string | null = null;

export const useAuth = () => {
  const router = useRouter();
  const hasHydrated = useAuthStoreHydrated();
  const [historyRestoreCount, setHistoryRestoreCount] = useState(0);
  const {
    user,
    expiresAt,
    isLoading,
    isSuperAdmin,
    setSession,
    setUser,
    updateExpiresAt,
    logout: clearSession,
    setLoading,
  } = useAuthStore();

  const accessToken = tokenStorage.getAccessToken();
  const refreshToken = tokenStorage.getRefreshToken();

  const isAuthenticated = useMemo(
    () => Boolean(accessToken && user && expiresAt && Date.now() < expiresAt),
    [accessToken, expiresAt, user],
  );

  usePageRestore(
    useCallback(() => {
      if (isLoading || authBootstrapPromise) {
        authBootstrapKey = null;
        authBootstrapPromise = null;
        setHistoryRestoreCount((count) => count + 1);
      }
    }, [isLoading]),
  );

  const establishSession = useCallback(
    async (payload: AuthTokenResponse) => {
      const access = payload.accessToken || payload.token;
      const refresh = payload.refreshToken;

      if (!access || !refresh) {
        throw new Error("Authentication response is missing tokens.");
      }

      const currentUser = await getCurrentUser(access);
      const session = normalizeAuthSession(payload, currentUser);
      setSession(session);

      return session;
    },
    [setSession],
  );

  const logout = useCallback(async () => {
    try {
      if (accessToken && refreshToken) {
        await logoutSession(accessToken, refreshToken);
      }
    } catch {
      // Logout should always clear local session, even if the API call fails.
    } finally {
      useFeatureFlagStore.getState().reset();
      clearSession();
      router.replace("/login");
    }
  }, [accessToken, clearSession, refreshToken, router]);

  useEffect(() => {
    if (!hasHydrated || !isLoading) {
      return;
    }

    let isActive = true;

    const initialize = async () => {
      if (!accessToken && !refreshToken) {
        if (isActive) {
          setLoading(false);
        }
        return;
      }

      try {
        const sessionClaims = accessToken
          ? decodeJWT<AuthTokenClaims>(accessToken)
          : null;
        const tokenExpiresAt =
          typeof sessionClaims?.exp === "number"
            ? sessionClaims.exp * 1_000
            : null;
        const effectiveExpiresAt = expiresAt ?? tokenExpiresAt;

        if (
          accessToken &&
          user &&
          effectiveExpiresAt &&
          Date.now() < effectiveExpiresAt
        ) {
          const hydratedUser = mergeUserWithClaims(user, sessionClaims);

          if (JSON.stringify(hydratedUser) !== JSON.stringify(user)) {
            if (isActive) {
              setUser(hydratedUser);
            }
          }
          if (expiresAt !== effectiveExpiresAt && isActive) {
            updateExpiresAt(effectiveExpiresAt);
          }

          if (isActive) {
            setLoading(false);
          }
          return;
        }

        if (
          accessToken &&
          effectiveExpiresAt &&
          Date.now() < effectiveExpiresAt
        ) {
          const currentUser = await getCurrentUser(accessToken);
          if (!isActive) {
            return;
          }

          setUser(
            mergeUserWithClaims(
              {
                id:
                  currentUser.userId != null
                    ? String(currentUser.userId)
                    : currentUser.email,
                email: currentUser.email,
                organizationId: currentUser.organizationId ?? null,
                organizationName: currentUser.organizationName ?? null,
                roles: currentUser.roles,
                permissions: currentUser.permissions,
                authMethod: currentUser.authMethod ?? null,
                mustChangePassword: currentUser.mustChangePassword ?? false,
              },
              sessionClaims,
            ),
          );
          if (expiresAt !== effectiveExpiresAt) {
            updateExpiresAt(effectiveExpiresAt);
          }
          return;
        }

        if (!refreshToken) {
          throw new Error("Refresh token missing.");
        }

        const refreshedSession = await refreshSession();
        const currentUser = await getCurrentUser(
          refreshedSession.accessToken || refreshedSession.token || "",
        );

        if (!isActive) {
          return;
        }

        setSession(
          normalizeAuthSession(
            {
              ...refreshedSession,
              authMethod: refreshedSession.authMethod ?? user?.authMethod,
            },
            currentUser,
          ),
        );
      } catch {
        if (isActive) {
          clearSession();
        }
      } finally {
        if (isActive) {
          setLoading(false);
        }
      }
    };

    const bootstrapKey = JSON.stringify({
      accessToken,
      refreshToken,
      expiresAt,
      userId: user?.id ?? null,
    });

    if (authBootstrapPromise && authBootstrapKey === bootstrapKey) {
      void authBootstrapPromise.finally(() => {
        if (isActive) {
          setLoading(false);
        }
      });
    } else {
      authBootstrapKey = bootstrapKey;
      authBootstrapPromise = initialize().finally(() => {
        authBootstrapPromise = null;
      });
    }

    return () => {
      isActive = false;
    };
  }, [
    accessToken,
    clearSession,
    expiresAt,
    historyRestoreCount,
    hasHydrated,
    isLoading,
    refreshToken,
    setLoading,
    setSession,
    setUser,
    updateExpiresAt,
    user,
  ]);

  return {
    user,
    expiresAt,
    accessToken,
    refreshToken,
    isAuthenticated,
    isLoading,
    isSuperAdmin,
    logout,
    establishSession,
  };
};
