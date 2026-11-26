// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import axios, { AxiosError } from "axios";

import { apiClient, publicApiClient, supportApiClient } from "@/lib/api";
import { useNetworkStatusStore } from "@/lib/network-status";

jest.mock("@/lib/logger/logger.service", () => ({
  logger: {
    debug: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
  },
}));

type AxiosRequestConfigLike = {
  headers?: Record<string, unknown>;
  [key: string]: unknown;
};

interface InterceptorManagerLike {
  handlers: Array<{
    fulfilled?: (value: any) => any;
    rejected?: (err: any) => any;
  }>;
}

interface AxiosInstanceLike {
  defaults: { timeout?: number };
  get: (...args: unknown[]) => Promise<unknown>;
  post: (...args: unknown[]) => Promise<unknown>;
  put: (...args: unknown[]) => Promise<unknown>;
  patch: (...args: unknown[]) => Promise<unknown>;
  delete: (...args: unknown[]) => Promise<unknown>;
  interceptors: {
    request: InterceptorManagerLike;
    response: InterceptorManagerLike;
  };
}

describe("api client wrappers", () => {
  const coreInstance = (
    apiClient as unknown as { axiosInstance: AxiosInstanceLike }
  ).axiosInstance;
  const supportInstance = (
    supportApiClient as unknown as { axiosInstance: AxiosInstanceLike }
  ).axiosInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    useNetworkStatusStore.getState().clearNetworkIssue();
  });

  it("bounds API requests so loading states cannot hang indefinitely", () => {
    expect(coreInstance.defaults.timeout).toBe(30_000);
    expect(supportInstance.defaults.timeout).toBe(30_000);
    expect(publicApiClient.defaults.timeout).toBe(30_000);
  });

  it("omits nullish query params without dropping valid falsy values", async () => {
    const getSpy = jest
      .spyOn(coreInstance, "get")
      .mockResolvedValue({ data: { ok: true } });

    await apiClient.get("/api/v1/pqc-readiness/certificates", {
      params: {
        quantumStatus: undefined,
        optionalFilter: null,
        page: 0,
        enabled: false,
        search: "",
        statuses: ["UNKNOWN", "DISALLOWED_2035"],
        sort: { direction: "desc", field: "createdAt" },
      },
    });

    expect(getSpy).toHaveBeenCalledWith("/api/v1/pqc-readiness/certificates", {
      params: {
        page: "0",
        enabled: "false",
        search: "",
        statuses: '["UNKNOWN","DISALLOWED_2035"]',
        sort: '{"direction":"desc","field":"createdAt"}',
      },
    });
  });

  it("adds X-Correlation-ID header for apiClient requests when missing", () => {
    const requestHandler = coreInstance.interceptors.request.handlers.find(
      (h) => typeof h?.fulfilled === "function",
    )?.fulfilled;
    expect(typeof requestHandler).toBe("function");

    const nextConfig = requestHandler!({
      headers: {},
    } as AxiosRequestConfigLike);
    expect(nextConfig.headers?.["X-Correlation-ID"]).toEqual(
      expect.any(String),
    );
    expect(String(nextConfig.headers?.["X-Correlation-ID"])).toMatch(
      /^corr-[0-9a-f-]{36}$/,
    );
  });

  it("preserves X-Correlation-ID header when already set", () => {
    const requestHandler = coreInstance.interceptors.request.handlers.find(
      (h) => typeof h?.fulfilled === "function",
    )?.fulfilled;
    expect(typeof requestHandler).toBe("function");

    const nextConfig = requestHandler!({
      headers: { "X-Correlation-ID": "corr-fixed" },
    } as AxiosRequestConfigLike);
    expect(nextConfig.headers?.["X-Correlation-ID"]).toBe("corr-fixed");
  });

  it("preserves lowercase x-correlation-id header when already set", () => {
    const requestHandler = coreInstance.interceptors.request.handlers.find(
      (h) => typeof h?.fulfilled === "function",
    )?.fulfilled;
    expect(typeof requestHandler).toBe("function");

    const nextConfig = requestHandler!({
      headers: { "x-correlation-id": "corr-lower" },
    } as AxiosRequestConfigLike);
    expect((nextConfig.headers as any)?.["x-correlation-id"]).toBe(
      "corr-lower",
    );
    expect(nextConfig.headers?.["X-Correlation-ID"]).toBeUndefined();
  });

  it("adds X-Correlation-ID header when config.headers is undefined", () => {
    const requestHandler = coreInstance.interceptors.request.handlers.find(
      (h) => typeof h?.fulfilled === "function",
    )?.fulfilled;
    expect(typeof requestHandler).toBe("function");

    const nextConfig = requestHandler!({} as AxiosRequestConfigLike);
    expect(nextConfig.headers?.["X-Correlation-ID"]).toEqual(
      expect.any(String),
    );
  });

  it("throws server unreachable for Axios network errors", async () => {
    jest
      .spyOn(coreInstance, "get")
      .mockRejectedValue(new AxiosError("Network Error", "ERR_NETWORK"));

    await expect(apiClient.get("/api/v1/organizations")).rejects.toThrow(
      "Server is unreachable",
    );
    expect(useNetworkStatusStore.getState().issue?.source).toBe("api");
  });

  it("maps response interceptor missing response to friendly error", async () => {
    const responseRejected = coreInstance.interceptors.response.handlers.find(
      (h) => typeof h?.rejected === "function",
    )?.rejected;
    expect(typeof responseRejected).toBe("function");

    await expect(responseRejected!({ config: { url: "/x" } })).rejects.toThrow(
      "Server is unreachable",
    );
    expect(useNetworkStatusStore.getState().issue?.source).toBe("api");
  });

  it("clears network issue after a successful core API response", async () => {
    const responseFulfilled = coreInstance.interceptors.response.handlers.find(
      (h) => typeof h?.fulfilled === "function",
    )?.fulfilled;
    expect(typeof responseFulfilled).toBe("function");

    useNetworkStatusStore
      .getState()
      .reportNetworkIssue("Backend unreachable", "api");

    const response = { data: { ok: true } };
    expect(responseFulfilled!(response)).toBe(response);
    expect(useNetworkStatusStore.getState().issue).toBeNull();
  });

  it("passes through response interceptor errors without original request config", async () => {
    const responseRejected = coreInstance.interceptors.response.handlers.find(
      (h) => typeof h?.rejected === "function",
    )?.rejected;
    expect(typeof responseRejected).toBe("function");

    const error = { response: { status: 500 }, config: undefined };
    await expect(responseRejected!(error)).rejects.toBe(error);
  });

  it("retries core request once after refresh token succeeds on 401", async () => {
    const coreClient = apiClient as unknown as {
      axiosInstance: any;
      refreshToken: () => Promise<{ accessToken: string } | null>;
    };
    const responseRejected =
      coreClient.axiosInstance.interceptors.response.handlers.find(
        (h: { rejected?: unknown }) => typeof h?.rejected === "function",
      )?.rejected as ((error: any) => Promise<unknown>) | undefined;
    expect(typeof responseRejected).toBe("function");

    const refreshSpy = jest
      .spyOn(coreClient, "refreshToken" as any)
      .mockResolvedValue({ accessToken: "access-2" });

    const originalAxiosInstance = coreClient.axiosInstance;
    const requestSpy = jest.fn().mockResolvedValue({ data: { ok: true } });
    coreClient.axiosInstance = Object.assign(requestSpy, originalAxiosInstance);

    const error = {
      response: { status: 401 },
      config: { headers: {}, _retry: false, url: "/api/v1/organizations" },
    };

    try {
      await expect(responseRejected!(error)).resolves.toEqual({
        data: { ok: true },
      });
      expect(refreshSpy).toHaveBeenCalledTimes(1);
      expect(requestSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          _retry: true,
          headers: expect.objectContaining({
            Authorization: "Bearer access-2",
          }),
        }),
      );
    } finally {
      coreClient.axiosInstance = originalAxiosInstance;
    }
  });

  it("adds X-Correlation-ID header for supportApiClient requests when missing", () => {
    const requestHandler = supportInstance.interceptors.request.handlers.find(
      (h) => typeof h?.fulfilled === "function",
    )?.fulfilled;
    expect(typeof requestHandler).toBe("function");

    const nextConfig = requestHandler!({
      headers: {},
    } as AxiosRequestConfigLike);
    expect(nextConfig.headers?.["X-Correlation-ID"]).toEqual(
      expect.any(String),
    );
  });

  it("passes through patch/put/delete happy paths", async () => {
    jest
      .spyOn(coreInstance, "patch")
      .mockResolvedValue({ data: { ok: "patch" } });
    jest.spyOn(coreInstance, "put").mockResolvedValue({ data: { ok: "put" } });
    jest
      .spyOn(coreInstance, "delete")
      .mockResolvedValue({ data: { ok: "delete" } });

    await expect(apiClient.patch("/x", { a: 1 })).resolves.toEqual({
      data: { ok: "patch" },
    });
    await expect(apiClient.put("/x", { a: 1 })).resolves.toEqual({
      data: { ok: "put" },
    });
    await expect(apiClient.delete("/x", { a: 1 })).resolves.toEqual({
      data: { ok: "delete" },
    });
  });

  it("maps support client network errors to friendly message", async () => {
    jest
      .spyOn(supportInstance, "get")
      .mockRejectedValue(new AxiosError("Network Error", "ERR_NETWORK"));

    await expect(
      supportApiClient.get("/api/v1/support/tickets"),
    ).rejects.toThrow("Something went wrong!");
  });

  it("retries support requests once after refreshing access token on 401", async () => {
    const supportClient = supportApiClient as unknown as {
      axiosInstance: any;
    };
    const coreClient = apiClient as unknown as {
      refreshAccessToken: () => Promise<string | null>;
    };

    const rejectedHandler =
      supportClient.axiosInstance.interceptors.response.handlers.find(
        (handler: { rejected?: unknown }) =>
          typeof handler?.rejected === "function",
      )?.rejected as ((error: any) => Promise<unknown>) | undefined;
    expect(typeof rejectedHandler).toBe("function");

    const refreshSpy = jest
      .spyOn(coreClient, "refreshAccessToken")
      .mockResolvedValue("access-1");

    const originalAxiosInstance = supportClient.axiosInstance;
    const requestSpy = jest.fn().mockResolvedValue({ data: { ok: true } });
    // Replace callable axios instance to observe retry behavior.
    supportClient.axiosInstance = Object.assign(
      requestSpy,
      originalAxiosInstance,
    );

    const error = {
      response: { status: 401 },
      config: { headers: {}, _retry: false },
    };

    try {
      await expect(rejectedHandler!(error)).resolves.toEqual({
        data: { ok: true },
      });
      expect(refreshSpy).toHaveBeenCalledTimes(1);
      expect(requestSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          _retry: true,
          headers: expect.objectContaining({
            Authorization: "Bearer access-1",
          }),
        }),
      );
    } finally {
      supportClient.axiosInstance = originalAxiosInstance;
    }
  });

  it("creates publicApiClient with json defaults", () => {
    expect(publicApiClient.defaults.headers["Content-Type"]).toBe(
      "application/json",
    );
    expect(publicApiClient.defaults.baseURL).toBeDefined();
  });

  it("adds X-Correlation-ID header for publicApiClient requests when missing", () => {
    const publicInstance = publicApiClient as unknown as AxiosInstanceLike;
    const requestHandler = publicInstance.interceptors.request.handlers.find(
      (h) => typeof h?.fulfilled === "function",
    )?.fulfilled;
    expect(typeof requestHandler).toBe("function");

    const nextConfig = requestHandler!({
      headers: {},
    } as AxiosRequestConfigLike);
    expect(nextConfig.headers?.["X-Correlation-ID"]).toEqual(
      expect.any(String),
    );
  });

  it("sends the refresh and the retried request under the original request's correlation ID", async () => {
    const coreClient = apiClient as unknown as { axiosInstance: any };
    const responseRejected =
      coreClient.axiosInstance.interceptors.response.handlers.find(
        (h: { rejected?: unknown }) => typeof h?.rejected === "function",
      )?.rejected as (error: any) => Promise<unknown>;

    const axiosPostSpy = jest.spyOn(axios, "post").mockResolvedValueOnce({
      data: {
        accessToken: "access-2",
        refreshToken: "refresh-2",
        expiresIn: 3600,
      },
    });
    const tokenStorageModule = await import("@/stores/auth-store");
    const refreshTokenSpy = jest
      .spyOn(tokenStorageModule.tokenStorage, "getRefreshToken")
      .mockReturnValue("refresh-token");
    const setTokensSpy = jest
      .spyOn(tokenStorageModule.tokenStorage, "setTokens")
      .mockImplementation(() => undefined);

    const originalAxiosInstance = coreClient.axiosInstance;
    const requestSpy = jest.fn().mockResolvedValue({ data: { ok: true } });
    coreClient.axiosInstance = Object.assign(requestSpy, originalAxiosInstance);

    try {
      await responseRejected({
        response: { status: 401 },
        config: {
          headers: { "X-Correlation-ID": "corr-original" },
          _retry: false,
          url: "/api/v1/organizations",
        },
      });

      expect(axiosPostSpy).toHaveBeenCalledWith(
        expect.stringContaining("/api/auth/refresh"),
        { refreshToken: "refresh-token" },
        expect.objectContaining({
          headers: expect.objectContaining({
            "X-Correlation-ID": "corr-original",
          }),
        }),
      );
      expect(requestSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: expect.objectContaining({
            "X-Correlation-ID": "corr-original",
            Authorization: "Bearer access-2",
          }),
        }),
      );
    } finally {
      coreClient.axiosInstance = originalAxiosInstance;
      axiosPostSpy.mockRestore();
      refreshTokenSpy.mockRestore();
      setTokensSpy.mockRestore();
    }
  });

  it("refreshes access token via public helper call path", async () => {
    const axiosPostSpy = jest.spyOn(axios, "post");
    axiosPostSpy.mockResolvedValueOnce({
      data: {
        accessToken: "new-access",
        refreshToken: "new-refresh",
        expiresIn: 3600,
      },
    });

    const tokenStorageModule = await import("@/stores/auth-store");
    const refreshTokenSpy = jest
      .spyOn(tokenStorageModule.tokenStorage, "getRefreshToken")
      .mockReturnValue("refresh-token");
    const setTokensSpy = jest.spyOn(
      tokenStorageModule.tokenStorage,
      "setTokens",
    );
    const updateExpiresSpy = jest
      .spyOn(tokenStorageModule.useAuthStore, "getState")
      .mockReturnValue({
        user: null,
        expiresAt: null,
        isLoading: false,
        isSuperAdmin: false,
        logout: jest.fn(),
        setSession: jest.fn(),
        setAuth: jest.fn(),
        setUser: jest.fn(),
        setLoading: jest.fn(),
        getAccessToken: jest.fn(),
        updateExpiresAt: jest.fn(),
      } as unknown as ReturnType<
        typeof tokenStorageModule.useAuthStore.getState
      >);

    const localStorageGetItemSpy = jest
      .spyOn(window.localStorage, "getItem")
      .mockReturnValue(null);

    await expect(apiClient.refreshAccessToken()).resolves.toBe("new-access");

    expect(axiosPostSpy).toHaveBeenCalledWith(
      expect.stringContaining("/api/auth/refresh"),
      { refreshToken: "refresh-token" },
      expect.objectContaining({ timeout: 30_000 }),
    );
    expect(refreshTokenSpy).toHaveBeenCalled();
    expect(setTokensSpy).toHaveBeenCalledWith("new-access", "new-refresh");
    expect(updateExpiresSpy).toHaveBeenCalled();
    // The store persists expiresAt itself; the legacy key is never read back.
    expect(localStorageGetItemSpy).not.toHaveBeenCalledWith(
      tokenStorageModule.LEGACY_AUTH_STORAGE_KEY,
    );

    axiosPostSpy.mockRestore();
    refreshTokenSpy.mockRestore();
    setTokensSpy.mockRestore();
    updateExpiresSpy.mockRestore();
    localStorageGetItemSpy.mockRestore();
  });

  it("shares one refresh request across concurrent auth callers", async () => {
    const tokenStorageModule = await import("@/stores/auth-store");
    const refreshTokenSpy = jest
      .spyOn(tokenStorageModule.tokenStorage, "getRefreshToken")
      .mockReturnValue("refresh-token");
    const axiosPostSpy = jest.spyOn(axios, "post");
    let resolveRefresh: ((value: unknown) => void) | undefined;
    axiosPostSpy.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveRefresh = resolve;
      }) as never,
    );

    const authBootstrapRefresh = apiClient.refreshAuthSession();
    const interceptorRefresh = apiClient.refreshAccessToken();

    expect(axiosPostSpy).toHaveBeenCalledTimes(1);
    resolveRefresh?.({
      data: {
        accessToken: "new-access",
        refreshToken: "new-refresh",
        expiresIn: 3600,
      },
    });

    await expect(authBootstrapRefresh).resolves.toEqual(
      expect.objectContaining({ accessToken: "new-access" }),
    );
    await expect(interceptorRefresh).resolves.toBe("new-access");

    axiosPostSpy.mockRestore();
    refreshTokenSpy.mockRestore();
  });

  it("returns null when refresh token is unavailable", async () => {
    const tokenStorageModule = await import("@/stores/auth-store");
    const getRefreshTokenSpy = jest
      .spyOn(tokenStorageModule.tokenStorage, "getRefreshToken")
      .mockReturnValue(null);
    const clearTokensSpy = jest.spyOn(
      tokenStorageModule.tokenStorage,
      "clearTokens",
    );
    const removeItemSpy = jest.spyOn(window.localStorage, "removeItem");

    await expect(apiClient.refreshAccessToken()).resolves.toBeNull();
    expect(getRefreshTokenSpy).toHaveBeenCalled();
    expect(clearTokensSpy).toHaveBeenCalled();
    expect(removeItemSpy).toHaveBeenCalledWith(
      tokenStorageModule.AUTH_STORAGE_KEY,
    );
    expect(removeItemSpy).toHaveBeenCalledWith(
      tokenStorageModule.LEGACY_AUTH_STORAGE_KEY,
    );

    getRefreshTokenSpy.mockRestore();
    clearTokensSpy.mockRestore();
    removeItemSpy.mockRestore();
  });

  it("passes through non-Axios errors from core API operations", async () => {
    jest.spyOn(coreInstance, "put").mockRejectedValue("plain-failure");

    await expect(apiClient.put("/api/v1/any", { ok: true })).rejects.toBe(
      "plain-failure",
    );
  });
});
