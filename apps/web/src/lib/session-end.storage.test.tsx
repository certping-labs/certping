// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { SsoUser } from "@/types/auth";

jest.mock("@/lib/browser-navigation", () => ({ loadPage: jest.fn() }));

jest.mock("@/lib/logger/logger.service", () => ({
  logger: { warn: jest.fn(), error: jest.fn(), info: jest.fn() },
}));

const profile = {
  id: "user-1",
  email: "maya@example.com",
  roles: ["ADMIN"],
} as unknown as SsoUser;

// A fresh registry per test, so no test inherits another's store or sign-out reason.
function loadModules() {
  return {
    ...(require("@/lib/session-end") as typeof import("@/lib/session-end")),
    ...(require("@/stores/auth-store") as typeof import("@/stores/auth-store")),
    loadPage: (
      require("@/lib/browser-navigation") as typeof import("@/lib/browser-navigation")
    ).loadPage as jest.Mock,
  };
}

describe("endSession", () => {
  beforeEach(() => {
    jest.resetModules();
    localStorage.clear();
    window.history.pushState({}, "", "/login");
  });

  it("leaves no saved profile or token after a forced sign-out", () => {
    const {
      endSession,
      useAuthStore,
      tokenStorage,
      AUTH_STORAGE_KEY,
      LEGACY_AUTH_STORAGE_KEY,
    } = loadModules();
    useAuthStore.getState().setAuth(profile, "access", "refresh", 9e12);
    localStorage.setItem(
      LEGACY_AUTH_STORAGE_KEY,
      JSON.stringify({ state: { user: profile } }),
    );
    expect(localStorage.getItem(AUTH_STORAGE_KEY)).toContain(
      "maya@example.com",
    );

    endSession("account-disabled");

    expect(localStorage.getItem(AUTH_STORAGE_KEY)).toBeNull();
    expect(localStorage.getItem(LEGACY_AUTH_STORAGE_KEY)).toBeNull();
    expect(tokenStorage.getAccessToken()).toBeNull();
    expect(tokenStorage.getRefreshToken()).toBeNull();
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("keeps the reason through the store reset and a later sign-out without one", () => {
    const { endSession, getPendingSignedOutReason, useAuthStore, loadPage } =
      loadModules();
    window.history.pushState({}, "", "/domains");
    useAuthStore.getState().setAuth(profile, "access", "refresh", 9e12);
    const userWhenLoaded: unknown[] = [];
    loadPage.mockImplementation(() =>
      userWhenLoaded.push(useAuthStore.getState().user),
    );

    endSession("organization-suspended");
    endSession();

    expect(loadPage.mock.calls).toEqual([
      ["/login?signedOut=organization-suspended"],
      ["/login?signedOut=organization-suspended"],
    ]);
    // The page load starts before the store reset makes the auth provider redirect too.
    expect(userWhenLoaded[0]).toEqual(profile);
    expect(getPendingSignedOutReason()).toBe("organization-suspended");
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("forgets the reason once a new session is set up", () => {
    const { endSession, getPendingSignedOutReason, useAuthStore, loadPage } =
      loadModules();
    window.history.pushState({}, "", "/integrations");
    endSession("organization-suspended");
    expect(getPendingSignedOutReason()).toBe("organization-suspended");

    // The page stayed (a cancelled unload), and the user signed in again.
    useAuthStore.getState().setAuth(profile, "access", "refresh", 9e12);
    expect(getPendingSignedOutReason()).toBeUndefined();

    endSession();
    expect(loadPage).toHaveBeenLastCalledWith("/login");
  });

  it("does not set a reason on a sign-in page, where it does not navigate", () => {
    const { endSession, getPendingSignedOutReason, loadPage } = loadModules();

    endSession("account-disabled");

    expect(loadPage).not.toHaveBeenCalled();
    expect(getPendingSignedOutReason()).toBeUndefined();
  });
});
