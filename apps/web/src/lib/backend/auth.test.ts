// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      post: jest.fn(),
      refreshAuthSession: jest.fn(),
    },
    publicApiClient: {
      post: jest.fn(),
      get: jest.fn(),
    },
  };
});

jest.mock("@/lib/utils", () => {
  const actual = jest.requireActual("@/lib/utils");
  return {
    ...actual,
    decodeJWT: jest.fn(),
  };
});

import { apiClient, publicApiClient } from "@/lib/api";
import {
  changePassword,
  exchangeSsoCode,
  getCurrentUser,
  loginUser,
  logoutSession,
  mergeUserWithClaims,
  normalizeAuthSession,
  refreshSession,
  setupAdmin,
} from "@/lib/backend/auth";
import { decodeJWT } from "@/lib/utils";

const mockedPublicApiClient = publicApiClient as unknown as {
  post: jest.Mock;
  get: jest.Mock;
};
const mockedApiClient = apiClient as unknown as {
  post: jest.Mock;
  refreshAuthSession: jest.Mock;
};

describe("backend auth", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("hydrates durable session from token and user payload", () => {
    const now = Date.now();
    jest.spyOn(Date, "now").mockReturnValue(now);
    (decodeJWT as jest.Mock).mockReturnValue({
      sub: "root@example.com",
      userId: 1,
      roles: ["SUPER_ADMIN"],
      permissions: ["*"],
    });

    const session = normalizeAuthSession(
      {
        accessToken: "access-token",
        refreshToken: "refresh-token",
        expiresIn: 3600,
        email: "bootstrap@example.com",
        roles: ["ORGANIZATION_ADMIN"],
        permissions: ["certificates:view"],
      },
      {
        email: "root@example.com",
        userId: 1,
        organizationId: null,
        organizationName: null,
        roles: ["SUPER_ADMIN"],
        permissions: ["*"],
      },
    );

    expect(session).toEqual({
      accessToken: "access-token",
      refreshToken: "refresh-token",
      expiresAt: now + 3600 * 1000,
      tokenType: "Bearer",
      isSuperAdmin: true,
      user: {
        id: "1",
        email: "root@example.com",
        organizationId: null,
        organizationName: null,
        roles: ["SUPER_ADMIN"],
        permissions: ["*"],
        authMethod: null,
        mustChangePassword: false,
      },
    });
  });

  it("throws when normalizeAuthSession payload is missing tokens", () => {
    expect(() =>
      normalizeAuthSession({
        email: "user@example.com",
        roles: [],
        permissions: [],
      }),
    ).toThrow("Authentication response did not include tokens.");
  });

  it("merges user claims with user payload fields", () => {
    const merged = mergeUserWithClaims(
      {
        id: "u-1",
        email: "old@example.com",
        organizationId: null,
        organizationName: null,
        roles: [],
        permissions: ["x"],
        authMethod: null,
      },
      {
        sub: "new@example.com",
        userId: "u-2",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["*"],
        authMethod: "SSO",
        mustChangePassword: false,
      },
    );

    expect(merged).toEqual({
      id: "u-2",
      email: "new@example.com",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: ["*"],
      authMethod: "SSO",
      mustChangePassword: false,
    });
  });

  it("keeps existing user values when claims are absent or partial", () => {
    const currentUser = {
      id: "u-1",
      email: "current@example.com",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["ORG_ADMIN"],
      permissions: ["cert:read"],
      authMethod: "LOCAL" as const,
    };

    expect(mergeUserWithClaims(currentUser, null)).toEqual(currentUser);
    expect(
      mergeUserWithClaims(currentUser, {
        permissions: "invalid-shape" as unknown as string[],
      }),
    ).toEqual(currentUser);
  });

  it("preserves required password changes from auth payloads and claims", () => {
    (decodeJWT as jest.Mock).mockReturnValue(null);

    const session = normalizeAuthSession({
      accessToken: "access-token",
      refreshToken: "refresh-token",
      email: "user@example.com",
      roles: ["USER"],
      permissions: [],
      mustChangePassword: true,
    });

    expect(session.user.mustChangePassword).toBe(true);
    expect(
      mergeUserWithClaims(
        {
          id: "u-1",
          email: "user@example.com",
          organizationId: null,
          organizationName: null,
          roles: [],
          permissions: [],
          authMethod: "LOCAL",
          mustChangePassword: false,
        },
        { mustChangePassword: true },
      ).mustChangePassword,
    ).toBe(true);
  });

  it("normalizes expiresIn and tokenType edge cases", () => {
    const now = Date.now();
    jest.spyOn(Date, "now").mockReturnValue(now);
    (decodeJWT as jest.Mock).mockReturnValue(null);

    const millisSession = normalizeAuthSession({
      accessToken: "access-token",
      refreshToken: "refresh-token",
      expiresIn: 120_000,
      tokenType: "Custom",
      email: "u@example.com",
      roles: [],
      permissions: [],
    });
    expect(millisSession.expiresAt).toBe(now + 120_000);
    expect(millisSession.tokenType).toBe("Custom");

    const fallbackSession = normalizeAuthSession({
      accessToken: "access-token-2",
      refreshToken: "refresh-token-2",
      expiresIn: 0,
      email: "u2@example.com",
      roles: [],
      permissions: [],
    });
    expect(fallbackSession.expiresAt).toBe(now + 3_600_000);
  });

  it("calls public auth endpoints and normalizes local authMethod defaults", async () => {
    mockedPublicApiClient.post.mockResolvedValue({
      data: {
        accessToken: "token",
        refreshToken: "refresh",
        email: "user@example.com",
        roles: [],
        permissions: [],
      },
    });

    await expect(
      setupAdmin({
        username: "admin",
        password: "Password!1",
        email: "admin@example.com",
        displayName: "Admin",
      }),
    ).resolves.toEqual(expect.objectContaining({ authMethod: "LOCAL" }));

    await expect(
      loginUser({
        identifier: "admin",
        password: "Password!1",
      }),
    ).resolves.toEqual(expect.objectContaining({ authMethod: "LOCAL" }));
    expect(mockedPublicApiClient.post).toHaveBeenCalledWith("/api/auth/login", {
      identifier: "admin",
      password: "Password!1",
    });

    mockedPublicApiClient.post.mockResolvedValueOnce({
      data: {
        accessToken: "token-2",
        refreshToken: "refresh-2",
        email: "sso@example.com",
        roles: [],
        permissions: [],
        authMethod: "SSO",
      },
    });
    await expect(
      loginUser({
        identifier: "admin",
        password: "Password!1",
      }),
    ).resolves.toEqual(expect.objectContaining({ authMethod: "SSO" }));
  });

  it("trades the SSO one-time code for a session and marks it as SSO", async () => {
    mockedPublicApiClient.post.mockResolvedValueOnce({
      data: { accessToken: "a", refreshToken: "r", expiresIn: 900 },
    });

    await expect(exchangeSsoCode("one-time")).resolves.toEqual({
      accessToken: "a",
      refreshToken: "r",
      expiresIn: 900,
      authMethod: "SSO",
    });
    expect(mockedPublicApiClient.post).toHaveBeenCalledWith(
      "/api/auth/sso/exchange",
      { code: "one-time" },
    );
  });

  it("calls refresh/current-user/logout and auth password endpoints", async () => {
    mockedApiClient.refreshAuthSession.mockResolvedValueOnce({
      refreshed: true,
    });
    mockedPublicApiClient.post.mockResolvedValueOnce({ data: {} });
    mockedPublicApiClient.get.mockResolvedValueOnce({
      data: { email: "user@example.com", roles: [], permissions: [] },
    });
    mockedApiClient.post.mockResolvedValueOnce({ data: {} });

    await expect(refreshSession()).resolves.toEqual({
      refreshed: true,
    });
    await expect(getCurrentUser("access-token")).resolves.toEqual(
      expect.objectContaining({ email: "user@example.com" }),
    );
    await expect(
      logoutSession("access-token", "refresh-token"),
    ).resolves.toBeUndefined();
    await expect(
      changePassword({
        currentPassword: "old",
        newPassword: "new",
        confirmPassword: "new",
      }),
    ).resolves.toBeUndefined();

    expect(mockedPublicApiClient.get).toHaveBeenCalledWith("/api/auth/me", {
      headers: {
        Authorization: "Bearer access-token",
      },
    });
    expect(mockedPublicApiClient.post).toHaveBeenCalledWith(
      "/api/auth/logout",
      { refreshToken: "refresh-token" },
      {
        headers: {
          Authorization: "Bearer access-token",
        },
      },
    );
    expect(mockedApiClient.post).toHaveBeenCalledWith(
      "/api/auth/change-password",
      {
        currentPassword: "old",
        newPassword: "new",
        confirmPassword: "new",
      },
    );
  });
});
