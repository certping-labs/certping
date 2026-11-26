// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { act, renderHook, waitFor } from "@testing-library/react";

import { useAuth } from "@/hooks/use-auth";
import type { SsoUser } from "@/types/auth";

const replaceMock = jest.fn();
const getCurrentUserMock = jest.fn();
const normalizeAuthSessionMock = jest.fn();
const refreshSessionMock = jest.fn();
const logoutSessionMock = jest.fn();
const mergeUserWithClaimsMock = jest.fn();
const decodeJwtMock = jest.fn();
const getAccessTokenMock = jest.fn();
const getRefreshTokenMock = jest.fn();
const setSessionMock = jest.fn();
const setUserMock = jest.fn();
const updateExpiresAtMock = jest.fn();
const clearSessionMock = jest.fn();
const setLoadingMock = jest.fn();
let storeState: {
  user: SsoUser | null;
  expiresAt: number | null;
  isLoading: boolean;
  isSuperAdmin: boolean;
};
let authStoreHydrated: boolean;

jest.mock("next/navigation", () => ({
  useRouter: () => ({
    replace: replaceMock,
  }),
}));

jest.mock("@/lib/backend/auth", () => ({
  getCurrentUser: (...args: unknown[]) => getCurrentUserMock(...args),
  mergeUserWithClaims: (...args: unknown[]) => mergeUserWithClaimsMock(...args),
  logoutSession: (...args: unknown[]) => logoutSessionMock(...args),
  normalizeAuthSession: (...args: unknown[]) =>
    normalizeAuthSessionMock(...args),
  refreshSession: (...args: unknown[]) => refreshSessionMock(...args),
}));

jest.mock("@/lib/utils", () => ({
  decodeJWT: (...args: unknown[]) => decodeJwtMock(...args),
}));

jest.mock("@/stores/auth-store", () => ({
  tokenStorage: {
    getAccessToken: () => getAccessTokenMock(),
    getRefreshToken: () => getRefreshTokenMock(),
  },
  useAuthStore: () => ({
    user: storeState.user,
    expiresAt: storeState.expiresAt,
    isLoading: storeState.isLoading,
    isSuperAdmin: storeState.isSuperAdmin,
    setSession: setSessionMock,
    setUser: setUserMock,
    updateExpiresAt: updateExpiresAtMock,
    logout: clearSessionMock,
    setLoading: setLoadingMock,
  }),
  useAuthStoreHydrated: () => authStoreHydrated,
}));

describe("useAuth", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    window.localStorage.clear();
    window.history.replaceState(null, "", "/");
    storeState = {
      user: null,
      expiresAt: null,
      isLoading: false,
      isSuperAdmin: false,
    };
    authStoreHydrated = true;
    getAccessTokenMock.mockReturnValue(null);
    getRefreshTokenMock.mockReturnValue(null);
    mergeUserWithClaimsMock.mockImplementation((value) => value);
    decodeJwtMock.mockReturnValue(null);
  });

  it("reports authenticated when token, user and future expiry are present", async () => {
    storeState = {
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: [],
        permissions: [],
        authMethod: "LOCAL",
      },
      expiresAt: Date.now() + 60_000,
      isLoading: false,
      isSuperAdmin: false,
    };
    getAccessTokenMock.mockReturnValue("access-token");

    const { result } = renderHook(() => useAuth());

    expect(result.current.isAuthenticated).toBe(true);
  });

  it("establishSession throws when auth payload omits tokens", async () => {
    const { result } = renderHook(() => useAuth());

    await expect(
      result.current.establishSession({
        email: "user@example.com",
        roles: [],
        permissions: [],
      }),
    ).rejects.toThrow("Authentication response is missing tokens.");
  });

  it("establishSession normalizes and stores session when current user resolves", async () => {
    getCurrentUserMock.mockResolvedValue({
      email: "user@example.com",
      userId: "u-1",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: ["certificate:read"],
      authMethod: "LOCAL",
    });
    normalizeAuthSessionMock.mockReturnValue({
      user: {
        id: "u-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
      },
      accessToken: "access-token",
      refreshToken: "refresh-token",
      expiresAt: Date.now() + 5000,
      tokenType: "Bearer",
      isSuperAdmin: false,
    });

    const { result } = renderHook(() => useAuth());

    await act(async () => {
      await result.current.establishSession({
        accessToken: "access-token",
        refreshToken: "refresh-token",
        email: "user@example.com",
        roles: [],
        permissions: [],
      });
    });

    expect(getCurrentUserMock).toHaveBeenCalledWith("access-token");
    expect(normalizeAuthSessionMock).toHaveBeenCalled();
    expect(setSessionMock).toHaveBeenCalled();
  });

  it("refreshes using refresh token during initialization when access token is expired", async () => {
    storeState = {
      user: null,
      expiresAt: Date.now() - 1_000,
      isLoading: true,
      isSuperAdmin: false,
    };
    getAccessTokenMock.mockReturnValue("expired-access");
    getRefreshTokenMock.mockReturnValue("refresh-token");
    refreshSessionMock.mockResolvedValue({
      accessToken: "new-access",
      refreshToken: "refresh-token",
      email: "user@example.com",
      roles: ["USER"],
      permissions: [],
      expiresIn: 3600,
    });
    getCurrentUserMock.mockResolvedValue({
      email: "user@example.com",
      userId: "u-1",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: [],
      authMethod: "LOCAL",
    });
    normalizeAuthSessionMock.mockReturnValue({
      user: {
        id: "u-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: [],
        authMethod: "LOCAL",
      },
      accessToken: "new-access",
      refreshToken: "refresh-token",
      expiresAt: Date.now() + 3600_000,
      tokenType: "Bearer",
      isSuperAdmin: false,
    });

    renderHook(() => useAuth());

    await waitFor(() => {
      expect(refreshSessionMock).toHaveBeenCalledWith();
      expect(setSessionMock).toHaveBeenCalled();
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
  });

  it("waits for persisted auth state before deciding whether to refresh", async () => {
    storeState = {
      user: null,
      expiresAt: null,
      isLoading: true,
      isSuperAdmin: false,
    };
    authStoreHydrated = false;
    getAccessTokenMock.mockReturnValue("access-token");
    getRefreshTokenMock.mockReturnValue("refresh-token");

    const { rerender } = renderHook(() => useAuth());

    expect(refreshSessionMock).not.toHaveBeenCalled();
    expect(setLoadingMock).not.toHaveBeenCalled();

    storeState = {
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: [],
        authMethod: "LOCAL",
      },
      expiresAt: Date.now() + 60_000,
      isLoading: true,
      isSuperAdmin: false,
    };
    authStoreHydrated = true;
    rerender();

    await waitFor(() => {
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
    expect(refreshSessionMock).not.toHaveBeenCalled();
  });

  it("uses the JWT expiry when persisted expiry has not been written yet", async () => {
    const jwtExpirySeconds = Math.floor(Date.now() / 1_000) + 60;
    storeState = {
      user: null,
      expiresAt: null,
      isLoading: true,
      isSuperAdmin: false,
    };
    getAccessTokenMock.mockReturnValue("access-token");
    getRefreshTokenMock.mockReturnValue("refresh-token");
    decodeJwtMock.mockReturnValue({
      sub: "user@example.com",
      exp: jwtExpirySeconds,
    });
    getCurrentUserMock.mockResolvedValue({
      email: "user@example.com",
      userId: "user-1",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: [],
      authMethod: "LOCAL",
    });

    renderHook(() => useAuth());

    await waitFor(() => {
      expect(getCurrentUserMock).toHaveBeenCalledWith("access-token");
      expect(setUserMock).toHaveBeenCalled();
      expect(updateExpiresAtMock).toHaveBeenCalledWith(
        jwtExpirySeconds * 1_000,
      );
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
    expect(refreshSessionMock).not.toHaveBeenCalled();
  });

  it("hydrates existing user from claims when session is still valid and profile changed", async () => {
    storeState = {
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
      },
      expiresAt: Date.now() + 90_000,
      isLoading: true,
      isSuperAdmin: false,
    };
    getAccessTokenMock.mockReturnValue("access-token");
    decodeJwtMock.mockReturnValue({ sub: "updated@example.com" });
    mergeUserWithClaimsMock.mockReturnValue({
      id: "user-1",
      email: "updated@example.com",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: ["certificate:read"],
      authMethod: "LOCAL",
    });

    renderHook(() => useAuth());

    await waitFor(() => {
      expect(setUserMock).toHaveBeenCalledWith(
        expect.objectContaining({ email: "updated@example.com" }),
      );
      expect(getCurrentUserMock).not.toHaveBeenCalled();
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
  });

  it("does not update user when claim merge produces the same user shape", async () => {
    const existingUser = {
      id: "user-1",
      email: "user@example.com",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: ["certificate:read"],
      authMethod: "LOCAL" as const,
    };
    storeState = {
      user: existingUser,
      expiresAt: Date.now() + 90_000,
      isLoading: true,
      isSuperAdmin: false,
    };
    getAccessTokenMock.mockReturnValue("access-token");
    decodeJwtMock.mockReturnValue({ sub: "user@example.com" });
    mergeUserWithClaimsMock.mockReturnValue(existingUser);

    renderHook(() => useAuth());

    await waitFor(() => {
      expect(setUserMock).not.toHaveBeenCalled();
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
  });

  it("marks loading complete immediately when no tokens are present", async () => {
    storeState = {
      user: null,
      expiresAt: null,
      isLoading: true,
      isSuperAdmin: false,
    };

    renderHook(() => useAuth());

    await waitFor(() => {
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
    expect(refreshSessionMock).not.toHaveBeenCalled();
  });

  it("clears session when access token is expired and refresh token is missing", async () => {
    storeState = {
      user: null,
      expiresAt: Date.now() - 1_000,
      isLoading: true,
      isSuperAdmin: false,
    };
    getAccessTokenMock.mockReturnValue("expired-access");
    getRefreshTokenMock.mockReturnValue(null);

    renderHook(() => useAuth());

    await waitFor(() => {
      expect(clearSessionMock).toHaveBeenCalled();
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
  });

  it("hydrates current user when access token is valid but user is missing", async () => {
    storeState = {
      user: null,
      expiresAt: Date.now() + 50_000,
      isLoading: true,
      isSuperAdmin: false,
    };
    getAccessTokenMock.mockReturnValue("access-token");
    getCurrentUserMock.mockResolvedValue({
      email: "user@example.com",
      userId: "u-1",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: ["certificate:read"],
      authMethod: "LOCAL",
    });
    decodeJwtMock.mockReturnValue({ sub: "claims@example.com" });
    mergeUserWithClaimsMock.mockImplementation((user) => user);

    renderHook(() => useAuth());

    await waitFor(() => {
      expect(getCurrentUserMock).toHaveBeenCalledWith("access-token");
      expect(setUserMock).toHaveBeenCalled();
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
  });

  it("clears loading for a remounted hook that reuses an in-flight bootstrap", async () => {
    storeState = {
      user: null,
      expiresAt: Date.now() + 50_000,
      isLoading: true,
      isSuperAdmin: false,
    };
    getAccessTokenMock.mockReturnValue("access-token");

    let resolveCurrentUser: (value: {
      email: string;
      userId: string;
      organizationId: string;
      organizationName: string;
      roles: string[];
      permissions: string[];
      authMethod: "LOCAL";
    }) => void;
    getCurrentUserMock.mockReturnValue(
      new Promise((resolve) => {
        resolveCurrentUser = resolve;
      }),
    );
    decodeJwtMock.mockReturnValue({ sub: "user@example.com" });
    mergeUserWithClaimsMock.mockImplementation((user) => user);

    const firstRender = renderHook(() => useAuth());
    firstRender.unmount();

    renderHook(() => useAuth());

    await act(async () => {
      resolveCurrentUser({
        email: "user@example.com",
        userId: "u-1",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["certificate:read"],
        authMethod: "LOCAL",
      });
    });

    await waitFor(() => {
      expect(setLoadingMock).toHaveBeenCalledWith(false);
    });
  });

  it("logout clears local session even when server logout fails", async () => {
    getAccessTokenMock.mockReturnValue("access-token");
    getRefreshTokenMock.mockReturnValue("refresh-token");
    logoutSessionMock.mockRejectedValue(new Error("server failure"));

    const { result } = renderHook(() => useAuth());

    await act(async () => {
      await result.current.logout();
    });

    expect(clearSessionMock).toHaveBeenCalled();
    expect(replaceMock).toHaveBeenCalledWith("/login");
  });

  it("logout calls server endpoint and redirects on success", async () => {
    getAccessTokenMock.mockReturnValue("access-token");
    getRefreshTokenMock.mockReturnValue("refresh-token");
    logoutSessionMock.mockResolvedValue(undefined);

    const { result } = renderHook(() => useAuth());

    await act(async () => {
      await result.current.logout();
    });

    expect(logoutSessionMock).toHaveBeenCalledWith(
      "access-token",
      "refresh-token",
    );
    expect(clearSessionMock).toHaveBeenCalled();
    expect(replaceMock).toHaveBeenCalledWith("/login");
  });

  it("logout skips server revocation when a stored token is missing", async () => {
    getAccessTokenMock.mockReturnValue("access-token");
    getRefreshTokenMock.mockReturnValue(null);

    const { result } = renderHook(() => useAuth());

    await act(async () => {
      await result.current.logout();
    });

    expect(logoutSessionMock).not.toHaveBeenCalled();
    expect(clearSessionMock).toHaveBeenCalled();
    expect(replaceMock).toHaveBeenCalledWith("/login");
  });

  it("establishSession accepts token fallback when accessToken is absent", async () => {
    getCurrentUserMock.mockResolvedValue({
      email: "user@example.com",
      userId: "u-1",
      organizationId: "org-1",
      organizationName: "Org",
      roles: [],
      permissions: [],
      authMethod: "LOCAL",
    });
    normalizeAuthSessionMock.mockReturnValue({
      user: {
        id: "u-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: [],
        permissions: [],
        authMethod: "LOCAL",
      },
      accessToken: "token-field",
      refreshToken: "refresh-token",
      expiresAt: Date.now() + 30_000,
      tokenType: "Bearer",
      isSuperAdmin: false,
    });

    const { result } = renderHook(() => useAuth());

    await act(async () => {
      await result.current.establishSession({
        token: "token-field",
        refreshToken: "refresh-token",
        email: "user@example.com",
        roles: [],
        permissions: [],
      });
    });

    expect(getCurrentUserMock).toHaveBeenCalledWith("token-field");
    expect(setSessionMock).toHaveBeenCalled();
  });
});
