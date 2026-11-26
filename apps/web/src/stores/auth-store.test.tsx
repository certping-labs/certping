// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { act } from "@testing-library/react";

import { tokenStorage, useAuthStore } from "@/stores/auth-store";

describe("auth-store tokenStorage", () => {
  beforeEach(() => {
    window.localStorage.clear();
    useAuthStore.setState({
      user: null,
      expiresAt: null,
      isLoading: true,
      isSuperAdmin: false,
    });
  });

  it("sets and gets access/refresh tokens", () => {
    tokenStorage.setTokens("access-1", "refresh-1");

    expect(tokenStorage.getAccessToken()).toBe("access-1");
    expect(tokenStorage.getRefreshToken()).toBe("refresh-1");
  });

  it("clears tokens", () => {
    tokenStorage.setTokens("access-1", "refresh-1");
    tokenStorage.clearTokens();

    expect(tokenStorage.getAccessToken()).toBeNull();
    expect(tokenStorage.getRefreshToken()).toBeNull();
  });
});

describe("useAuthStore state actions", () => {
  beforeEach(() => {
    window.localStorage.clear();
    useAuthStore.setState({
      user: null,
      expiresAt: null,
      isLoading: true,
      isSuperAdmin: false,
    });
  });

  it("setSession updates user and auth metadata", () => {
    act(() => {
      useAuthStore.getState().setSession({
        user: {
          id: "u-1",
          email: "user@example.com",
          organizationId: "org-1",
          organizationName: "Org",
          roles: ["SUPER_ADMIN"],
          permissions: ["*"],
          authMethod: "LOCAL",
        },
        accessToken: "access-1",
        refreshToken: "refresh-1",
        expiresAt: Date.now() + 60_000,
        tokenType: "Bearer",
        isSuperAdmin: true,
      });
    });

    const state = useAuthStore.getState();
    expect(state.user?.id).toBe("u-1");
    expect(state.isSuperAdmin).toBe(true);
    expect(state.isLoading).toBe(false);
    expect(tokenStorage.getAccessToken()).toBe("access-1");
  });

  it("setAuth infers super admin from roles", () => {
    act(() => {
      useAuthStore.getState().setAuth(
        {
          id: "u-2",
          email: "user2@example.com",
          organizationId: "org-2",
          organizationName: "Org 2",
          roles: ["USER"],
          permissions: [],
          authMethod: "SSO",
        },
        "access-2",
        "refresh-2",
        Date.now() + 120_000,
      );
    });

    const state = useAuthStore.getState();
    expect(state.user?.id).toBe("u-2");
    expect(state.isSuperAdmin).toBe(false);
    expect(state.isLoading).toBe(false);
  });

  it("logout resets store and clears token storage", () => {
    act(() => {
      useAuthStore.getState().setSession({
        user: {
          id: "u-1",
          email: "user@example.com",
          organizationId: "org-1",
          organizationName: "Org",
          roles: ["SUPER_ADMIN"],
          permissions: ["*"],
          authMethod: "LOCAL",
        },
        accessToken: "access-1",
        refreshToken: "refresh-1",
        expiresAt: Date.now() + 60_000,
        tokenType: "Bearer",
        isSuperAdmin: true,
      });
      useAuthStore.getState().logout();
    });

    const state = useAuthStore.getState();
    expect(state.user).toBeNull();
    expect(state.expiresAt).toBeNull();
    expect(state.isLoading).toBe(true);
    expect(state.isSuperAdmin).toBe(false);
    expect(tokenStorage.getAccessToken()).toBeNull();
  });

  it("updates user/loading/expiry and exposes token getter", () => {
    tokenStorage.setTokens("access-3", "refresh-3");

    act(() => {
      useAuthStore.getState().setUser({
        id: "u-3",
        email: "user3@example.com",
        organizationId: null,
        organizationName: null,
        roles: ["SUPER_ADMIN"],
        permissions: [],
        authMethod: "LOCAL",
      });
      useAuthStore.getState().updateExpiresAt(Date.now() + 99_000);
      useAuthStore.getState().setLoading(false);
    });

    const state = useAuthStore.getState();
    expect(state.user?.id).toBe("u-3");
    expect(state.isSuperAdmin).toBe(true);
    expect(state.expiresAt).toBeGreaterThan(Date.now());
    expect(state.isLoading).toBe(false);
    expect(state.getAccessToken()).toBe("access-3");
  });
});
