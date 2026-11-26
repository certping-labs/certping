// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";
import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { SignedOutReason } from "@/lib/signed-out-reason";
import { AuthSession, SsoUser } from "@/types/auth";

// Token storage keys
const ACCESS_TOKEN_KEY = "accessToken";
const REFRESH_TOKEN_KEY = "refreshToken";

/** Where the persisted profile lives; the legacy key is only ever cleared, never read. */
export const AUTH_STORAGE_KEY = "auth-storage-v2";
export const LEGACY_AUTH_STORAGE_KEY = "auth-storage";

// Helper functions for token management
export const tokenStorage = {
  getAccessToken: (): string | null => {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  },
  getRefreshToken: (): string | null => {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  },
  setTokens: (accessToken: string, refreshToken: string) => {
    if (typeof window === "undefined") return;
    localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  },
  clearTokens: () => {
    if (typeof window === "undefined") return;
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  },
};

interface AuthState {
  user: SsoUser | null;
  expiresAt: number | null;
  isLoading: boolean;
  isSuperAdmin: boolean;
  /** Why a forced sign-out is leaving this page; not persisted, and cleared by the next session. */
  signedOutReason: SignedOutReason | null;
  setSession: (session: AuthSession) => void;
  setAuth: (
    user: SsoUser,
    accessToken: string,
    refreshToken: string,
    expiresAt: number,
  ) => void;
  setUser: (user: SsoUser) => void;
  updateExpiresAt: (expiresAt: number | null) => void;
  logout: () => void;
  setLoading: (loading: boolean) => void;
  getAccessToken: () => string | null;
}

const initialState = {
  user: null,
  expiresAt: null,
  isLoading: true,
  isSuperAdmin: false,
  signedOutReason: null,
};

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      ...initialState,

      setSession: (session: AuthSession) => {
        tokenStorage.setTokens(session.accessToken, session.refreshToken);
        set({
          user: session.user,
          expiresAt: session.expiresAt,
          isSuperAdmin: session.isSuperAdmin,
          isLoading: false,
          signedOutReason: null,
        });
      },

      setAuth: (
        user: SsoUser,
        accessToken: string,
        refreshToken: string,
        expiresAt: number,
      ) => {
        tokenStorage.setTokens(accessToken, refreshToken);
        set({
          user,
          expiresAt,
          isSuperAdmin: user.roles.includes("SUPER_ADMIN"),
          isLoading: false,
          signedOutReason: null,
        });
      },

      setUser: (user: SsoUser) =>
        set({
          user,
          isSuperAdmin: user.roles.includes("SUPER_ADMIN"),
        }),

      updateExpiresAt: (expiresAt: number | null) => set({ expiresAt }),

      logout: () => {
        tokenStorage.clearTokens();
        set(initialState);
      },

      setLoading: (loading: boolean) => set({ isLoading: loading }),

      getAccessToken: () => tokenStorage.getAccessToken(),
    }),
    {
      name: AUTH_STORAGE_KEY,
      partialize: (state) => ({
        user: state.user,
        expiresAt: state.expiresAt,
        isSuperAdmin: state.isSuperAdmin,
      }),
    },
  ),
);

export const useAuthStoreHydrated = (): boolean => {
  const [hasHydrated, setHasHydrated] = useState(() =>
    typeof window === "undefined" ? false : useAuthStore.persist.hasHydrated(),
  );

  useEffect(() => {
    const unsubscribeHydrate = useAuthStore.persist.onHydrate(() =>
      setHasHydrated(false),
    );
    const unsubscribeFinishHydration = useAuthStore.persist.onFinishHydration(
      () => setHasHydrated(true),
    );

    setHasHydrated(useAuthStore.persist.hasHydrated());

    return () => {
      unsubscribeHydrate();
      unsubscribeFinishHydration();
    };
  }, []);

  return hasHydrated;
};
