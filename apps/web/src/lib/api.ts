// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiBaseUrl } from "@/lib/api-base-url";
import axios, {
  AxiosError,
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
} from "axios";

import { logger } from "./logger/logger.service";
import { tokenStorage, useAuthStore } from "@/stores/auth-store";
import {
  generateCorrelationId,
  normalizeExpiresInMs,
  normalizeOrganizationIds,
} from "@/lib/api-helpers";
import {
  CORRELATION_ID_HEADER,
  ensureCorrelationId,
  readCorrelationId,
  unreachableError,
} from "@/lib/correlation-id";
import { endSession, getAccountRefusal } from "@/lib/session-end";
import { logHttpClientFailure } from "@/lib/logger/http-failure-log";
import { clearNetworkIssue, reportApiNetworkIssue } from "@/lib/network-status";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { queryClient } from "@/providers/react-query";
import type { AuthTokenResponse } from "@/types/auth";

interface ApiConfig {
  baseURL: string;
  headers: {
    "Content-Type": string;
  };
  withCredentials: boolean;
  timeout: number;
}

const API_REQUEST_TIMEOUT_MS = 30_000;

const baseURL = apiBaseUrl();

export const resolveApiUrl = (
  url: string | null | undefined,
): string | null => {
  if (!url) {
    return null;
  }

  try {
    return new URL(url, baseURL).toString();
  } catch {
    return url;
  }
};

export const apiRoutes = {
  query: {
    auth: {
      currentUser: "/api/auth/me",
      /** Public: true until the first Platform Super Admin exists. */
      setupStatus: "/api/auth/setup/status",
      /** Whether the signed-in account has a TOTP second factor. */
      mfa: "/api/auth/mfa",
    },
    organization: {
      list: "/api/v1/organizations",
      organizationById: (organizationId: string | number) =>
        `/api/v1/organizations/${encodeURIComponent(String(organizationId))}`,
      organizationBySlug: (slug: string) =>
        `/api/v1/organizations/slug/${encodeURIComponent(slug)}`,
      organizationByName: (organizationName: string) =>
        `/api/v1/organizations/name/${encodeURIComponent(organizationName)}`,
      organizationByDomain: (domain: string) =>
        `/api/v1/organizations/domain/${encodeURIComponent(domain)}`,
      retentionSettings: (orgId: string | number) =>
        `/api/v1/organizations/${encodeURIComponent(String(orgId))}/settings/soft-delete-retention`,
      notificationSettings: (orgId: string | number) =>
        `/api/v1/organizations/${encodeURIComponent(String(orgId))}/settings/notifications`,
    },
    certs: {
      list: "/api/v1/certs",
      expiring: "/api/v1/certs/expiring",
      valueSummary: "/api/v1/certs/value-summary",
      cbom: "/api/v1/cbom",
      pqcReadiness: "/api/v1/pqc-readiness",
      pqcReadinessCertificates: "/api/v1/pqc-readiness/certificates",
      detail: (certificateXref: string) =>
        `/api/v1/certs/${encodeURIComponent(certificateXref)}`,
      txtRecords: (certificateXref: string) =>
        `/api/v1/certs/${encodeURIComponent(certificateXref)}/txt-records`,
      history: "/api/v1/certs/history",
    },
    ssl: {
      certificateDetails: "/api/certificate/details",
      certificateDetailsByXref: "/api/certificate/details/xref",
      certificate: "/api/certificate",
      privateKey: "/api/certificate/private-key",
      certificateChain: "/api/certificate/chain",
      account: "/api/account",
      manualTxtRecord: "/api/certificate/manual/txt-record",
      alerts: "/api/alerts",
    },
    credentials: {
      list: "/api/v1/credentials",
      detail: (credentialXref: string) =>
        `/api/v1/credentials/${encodeURIComponent(credentialXref)}`,
    },
    certificateAuthorities: "/api/v1/certificate-authorities",
    discovery: {
      certs: "/api/v1/discovery/certs",
      cert: (id: number | string) =>
        `/api/v1/discovery/certs/${encodeURIComponent(String(id))}`,
      triggerConfigs: "/api/v1/discovery/trigger",
      triggerConfig: (configId: number | string) =>
        `/api/v1/discovery/trigger/${encodeURIComponent(String(configId))}`,
    },
    deployment: {
      list: "/api/v1/deployments",
      userDomainCertSummary: "/api/v1/deployments/user-domain-certs/summary",
      credentialConfig: "/api/v1/deployments/cred-config",
    },
    incidents: {
      sslAlerts: "/api/v1/alerts",
      notifications: "/api/notifications",
    },
    agent: {
      health: "/api/v1/agent/health",
      healthCadence: "/api/v1/agent/health/cadence",
      tokens: "/api/v1/agent-tokens",
      tokenById: (tokenId: number | string) =>
        `/api/v1/agent-tokens/${encodeURIComponent(String(tokenId))}`,
      agents: "/api/v1/agents",
      agentById: (agentId: number | string) =>
        `/api/v1/agents/${encodeURIComponent(String(agentId))}`,
      deepCheck: (deepCheckId: string) =>
        `/api/v1/agent/health/deep-checks/${encodeURIComponent(deepCheckId)}`,
      deepCheckMetrics: (deepCheckId: string) =>
        `/api/v1/agent/health/deep-checks/${encodeURIComponent(deepCheckId)}/metrics`,
    },
    audit: {
      list: "/api/v1/audit-logs",
      resources: "/api/v1/audit-logs/resources",
      actions: "/api/v1/audit-logs/actions",
      categories: "/api/v1/audit-logs/categories",
      // An older server answers 404 for these; the audit page reads that as
      // "not available yet", not as a failure.
      export: "/api/v1/audit-logs/export",
      accessList: "/api/v1/audit-logs/access",
      accessExport: "/api/v1/audit-logs/access/export",
      accessActivities: "/api/v1/audit-logs/access/activities",
      platformList: "/api/v1/admin/audit-logs",
      platformExport: "/api/v1/admin/audit-logs/export",
      platformResources: "/api/v1/admin/audit-logs/resources",
      platformActions: "/api/v1/admin/audit-logs/actions",
      platformCategories: "/api/v1/admin/audit-logs/categories",
    },
    users: {
      list: "/api/v1/users",
      organizationList: "/api/v1/users/organization",
      detail: (id: number | string) =>
        `/api/v1/users/${encodeURIComponent(String(id))}`,
      permissions: (id: number | string) =>
        `/api/v1/users/${encodeURIComponent(String(id))}/permissions`,
    },
    roles: {
      list: "/api/v1/roles",
      detail: (id: number | string) =>
        `/api/v1/roles/${encodeURIComponent(String(id))}`,
      permissions: (id: number | string) =>
        `/api/v1/roles/${encodeURIComponent(String(id))}/permissions`,
    },
    permissions: {
      list: "/api/v1/permissions",
      byResource: (resource: string) =>
        `/api/v1/permissions/resource/${encodeURIComponent(resource)}`,
    },
    integrations: {
      list: "/api/v1/integrations",
      detail: (integrationId: number | string) =>
        `/api/v1/integrations/${encodeURIComponent(String(integrationId))}`,
    },
    supportIncidents: {
      list: "/api/v1/incidents",
    },
    deploymentInfo: "/api/v1/deployment-info",
    featureFlags: {
      // Any signed-in user with an organization; no permission needed.
      effective: "/api/v1/feature-flags/effective",
    },
    admin: {
      auditRetentionSettings: "/api/v1/admin/settings/audit-retention",
      passwordHashInventory: "/api/v1/admin/password-hash/inventory",
    },
    /** Device sources, device inventory, and certificates, synced via the CertPing agent. */
    iotDevices: {
      sources: "/api/v1/iot/sources",
      sourceEvents: (sourceXref: string) =>
        `/api/v1/iot/sources/${encodeURIComponent(sourceXref)}/events`,
      devices: "/api/v1/iot/devices",
      device: (deviceXref: string) =>
        `/api/v1/iot/devices/${encodeURIComponent(deviceXref)}`,
      deviceEvents: (deviceXref: string) =>
        `/api/v1/iot/devices/${encodeURIComponent(deviceXref)}/events`,
      deviceCertificates: (deviceXref: string) =>
        `/api/v1/iot/devices/${encodeURIComponent(deviceXref)}/certificates`,
      summary: "/api/v1/iot/summary",
      caConnectors: "/api/v1/iot/ca-connectors",
      caConnector: (connectorId: string) =>
        `/api/v1/iot/ca-connectors/${encodeURIComponent(connectorId)}`,
      certificates: "/api/v1/iot/certificates",
      certificate: (certificateXref: string) =>
        `/api/v1/iot/certificates/${encodeURIComponent(certificateXref)}`,
      certificateHistory: (certificateXref: string) =>
        `/api/v1/iot/certificates/${encodeURIComponent(certificateXref)}/history`,
    },
    /** Certificate profile templates (e.g. Intune Windows SCEP profiles). */
    machineIdentityProfiles: {
      list: "/api/v1/machine-identity/profiles",
      detail: (profileXref: string) =>
        `/api/v1/machine-identity/profiles/${encodeURIComponent(profileXref)}`,
      events: (profileXref: string) =>
        `/api/v1/machine-identity/profiles/${encodeURIComponent(profileXref)}/events`,
    },
  },
  mutation: {
    auth: {
      refresh: "/api/auth/refresh",
      validate: "/api/auth/validate",
      logout: "/api/auth/logout",
      login: "/api/auth/login",
      /** Public: trades the one-time code from the SSO redirect for a session. */
      ssoExchange: "/api/auth/sso/exchange",
      /** Public, first run only: creates the first Platform Super Admin. */
      setup: "/api/auth/setup",
      forgotPassword: "/api/auth/forgot-password",
      resetPassword: (token: string) =>
        `/api/auth/reset-password/${encodeURIComponent(token)}`,
      changePassword: "/api/auth/change-password",
      /** Second sign-in step: the mfaToken from login plus a one-time or recovery code. */
      loginMfa: "/api/auth/login/mfa",
      mfaEnroll: "/api/auth/mfa/enroll",
      mfaConfirm: "/api/auth/mfa/confirm",
      /** DELETE with the account's password. */
      mfaDisable: "/api/auth/mfa",
      /** DELETE, users:manage: clears a member's second factor so they can enroll again. */
      mfaReset: (userId: number | string) =>
        `/api/v1/users/${encodeURIComponent(String(userId))}/mfa`,
    },
    admin: {
      setup: "/api/v1/admin/organization-admin/setup",
      /** PUT, super admin: the organization the signed-in super admin works in. */
      workingOrganization: "/api/v1/admin/me/organization",
      globalRetentionSettings: "/api/v1/admin/settings/soft-delete-retention",
      auditRetentionSettings: "/api/v1/admin/settings/audit-retention",
      passwordHashRotate: (batchSize: number | string) =>
        `/api/v1/admin/password-hash/rotate?batchSize=${encodeURIComponent(String(batchSize))}`,
    },
    organization: {
      create: "/api/v1/organizations",
      update: (organizationId: string | number) =>
        `/api/v1/organizations/${encodeURIComponent(String(organizationId))}`,
      delete: (organizationId: string | number) =>
        `/api/v1/organizations/${encodeURIComponent(String(organizationId))}`,
      purgeSoftDeleted: (orgId: string | number) =>
        `/api/v1/organizations/${encodeURIComponent(String(orgId))}/purge-soft-deleted`,
      retentionSettings: (orgId: string | number) =>
        `/api/v1/organizations/${encodeURIComponent(String(orgId))}/settings/soft-delete-retention`,
      notificationSettings: (orgId: string | number) =>
        `/api/v1/organizations/${encodeURIComponent(String(orgId))}/settings/notifications`,
    },
    certs: {
      issue: "/api/v1/certs/issue",
      issueManual: "/api/v1/certs/issue-manual",
      convertToAutomated: (certificateXref: string) =>
        `/api/v1/certs/${encodeURIComponent(certificateXref)}/convert-to-automated`,
      renew: (certificateXref: string) =>
        `/api/v1/certs/${encodeURIComponent(certificateXref)}/renew`,
      deploy: (certificateXref: string) =>
        `/api/v1/certs/${encodeURIComponent(certificateXref)}/deploy`,
      revoke: (certificateXref: string) =>
        `/api/v1/certs/${encodeURIComponent(certificateXref)}/revoke`,
      export: (certificateXref: string) =>
        `/api/v1/certs/${encodeURIComponent(certificateXref)}/export`,
      delete: (userDomainCertId: string | number) =>
        `/api/v1/user-domain-certificates/${encodeURIComponent(String(userDomainCertId))}`,
      validateDns: (certificateXref: string) =>
        `/api/v1/certs/${encodeURIComponent(certificateXref)}/validate-dns`,
    },
    ssl: {
      requestManualTxtRecord: "/api/certificate/manual/txt-record",
      completeManualDnsChallenge: "/api/certificate/manual/dns-challenge",
      automatedDnsChallenge: "/api/certificate/auto/dns-challenge",
      renewCertificate: "/api/certificate/renew",
      revokeCertificate: "/api/certificate/revoke",
      deleteCertificate: "/api/certificate/delete",
      storeAccount: "/api/account",
      markAlertAsRead: (id: number | string) =>
        `/api/v1/alerts/${encodeURIComponent(String(id))}`,
    },
    credentials: {
      createDns: "/api/v1/credentials/dns",
      createDeployment: "/api/v1/credentials/deployment",
      createCa: "/api/v1/credentials/ca",
      ca: (credentialXref: string) =>
        `/api/v1/credentials/ca/${encodeURIComponent(credentialXref)}`,
      createDiscovery: "/api/v1/credentials/discovery",
      update: (credentialXref: string) =>
        `/api/v1/credentials/${encodeURIComponent(credentialXref)}`,
      delete: (credentialXref: string) =>
        `/api/v1/credentials/${encodeURIComponent(credentialXref)}`,
    },
    discovery: {
      trigger: "/api/v1/discovery/trigger",
      triggerAll: "/api/v1/discovery/trigger/all",
      triggerConfig: (configId: number | string) =>
        `/api/v1/discovery/trigger/${encodeURIComponent(String(configId))}`,
    },
    domainCredentialConfig: {
      patchDns: (domain: string) =>
        `/api/v1/certs/domains/${encodeURIComponent(domain)}/credential-config/dns`,
      addDeploymentTarget: (domain: string) =>
        `/api/v1/certs/domains/${encodeURIComponent(domain)}/credential-config/deployment-targets`,
      removeDeploymentTarget: (domain: string, credentialXref: string) =>
        `/api/v1/certs/domains/${encodeURIComponent(domain)}/credential-config/deployment-targets/${encodeURIComponent(
          credentialXref,
        )}`,
    },
    incidents: {
      markSslAlertAsRead: (id: number | string) =>
        `/api/v1/alerts/${encodeURIComponent(String(id))}`,
    },
    agent: {
      updateHealthCadence: "/api/v1/agent/health/cadence",
      runHealthCheck: (agentId: number | string) =>
        `/api/v1/agents/${encodeURIComponent(String(agentId))}/health-check`,
    },
    users: {
      create: "/api/v1/admin/users",
      update: (id: number | string) =>
        `/api/v1/users/${encodeURIComponent(String(id))}`,
      organizationUpdate: (id: number | string) =>
        `/api/v1/users/organization/${encodeURIComponent(String(id))}`,
      delete: (id: number | string) =>
        `/api/v1/users/${encodeURIComponent(String(id))}`,
      organizationDelete: (id: number | string) =>
        `/api/v1/users/organization/${encodeURIComponent(String(id))}`,
      disable: (id: number | string) =>
        `/api/v1/users/${encodeURIComponent(String(id))}/disable`,
      organizationDisable: (id: number | string) =>
        `/api/v1/users/organization/${encodeURIComponent(String(id))}/disable`,
      assignRoles: (id: number | string) =>
        `/api/v1/users/${encodeURIComponent(String(id))}/roles`,
      updatePermissions: (id: number | string) =>
        `/api/v1/users/${encodeURIComponent(String(id))}/permissions`,
    },
    roles: {
      create: "/api/v1/roles",
      delete: (id: number | string) =>
        `/api/v1/roles/${encodeURIComponent(String(id))}`,
      updatePermissions: (id: number | string) =>
        `/api/v1/roles/${encodeURIComponent(String(id))}/permissions`,
    },
    integrations: {
      create: "/api/v1/integrations",
      update: (integrationId: number | string) =>
        `/api/v1/integrations/${encodeURIComponent(String(integrationId))}`,
      delete: (integrationId: number | string) =>
        `/api/v1/integrations/${encodeURIComponent(String(integrationId))}`,
    },
    supportIncidents: {
      createPagerDuty: "/api/v1/incidents/pagerduty",
      createServiceNow: "/api/v1/incidents/service-now",
    },
    iotDevices: {
      sourceSync: (sourceXref: string) =>
        `/api/v1/iot/sources/${encodeURIComponent(sourceXref)}/sync`,
      sourceSyncStop: (sourceXref: string) =>
        `/api/v1/iot/sources/${encodeURIComponent(sourceXref)}/sync/stop`,
      deviceDecommission: (deviceXref: string) =>
        `/api/v1/iot/devices/${encodeURIComponent(deviceXref)}/decommission`,
      /** Hides an orphaned device from the inventory. Soft: nothing is deleted. */
      deviceArchive: (deviceXref: string) =>
        `/api/v1/iot/devices/${encodeURIComponent(deviceXref)}/archive`,
      deviceRestore: (deviceXref: string) =>
        `/api/v1/iot/devices/${encodeURIComponent(deviceXref)}/restore`,
      /** Requires an `Idempotency-Key` header; replies `202 Accepted`. */
      certificateRevoke: (certificateXref: string) =>
        `/api/v1/iot/certificates/${encodeURIComponent(certificateXref)}/revoke`,
      /** Requests an Intune check-in for selected devices, or all with `?all=true`. */
      certificateNudge: "/api/v1/iot/certificates/nudge",
    },
    machineIdentityProfiles: {
      create: "/api/v1/machine-identity/profiles",
      update: (profileXref: string) =>
        `/api/v1/machine-identity/profiles/${encodeURIComponent(profileXref)}`,
      /** Soft-deletes a profile a completed sync proved is gone from the provider. */
      archive: (profileXref: string) =>
        `/api/v1/machine-identity/profiles/${encodeURIComponent(profileXref)}`,
      sourceProfilesSync: (sourceXref: string) =>
        `/api/v1/machine-identity/sources/${encodeURIComponent(sourceXref)}/profiles/sync`,
    },
  },
};

const API_CONFIG: ApiConfig = {
  baseURL: baseURL,
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true,
  timeout: API_REQUEST_TIMEOUT_MS,
};

class ApiClient {
  private static instance: ApiClient;
  private axiosInstance: AxiosInstance;
  private isRefreshing = false;
  private refreshPromise: Promise<AuthTokenResponse | null> | null = null;

  private constructor() {
    this.axiosInstance = axios.create(API_CONFIG);
    this.setupRequestInterceptor();
    this.setupResponseInterceptor();
  }

  public static getInstance(): ApiClient {
    if (!ApiClient.instance) {
      ApiClient.instance = new ApiClient();
    }
    return ApiClient.instance;
  }
  private getAccessToken(): string | null {
    return tokenStorage.getAccessToken();
  }

  private getRefreshToken(): string | null {
    return tokenStorage.getRefreshToken();
  }

  private setupRequestInterceptor(): void {
    this.axiosInstance.interceptors.request.use(
      (config) => {
        config.data = normalizeOrganizationIds(config.data);
        config.headers = config.headers ?? {};
        ensureCorrelationId(config.headers);

        const token = this.getAccessToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      undefined,
      { synchronous: true },
    );
  }

  private setupResponseInterceptor(): void {
    this.axiosInstance.interceptors.response.use(
      (response) => {
        clearNetworkIssue();
        return response;
      },
      async (error) => {
        if (!error.response) {
          logHttpClientFailure(error);
          reportApiNetworkIssue();
          return Promise.reject(
            unreachableError("Server is unreachable", error.config?.headers),
          );
        }

        clearNetworkIssue();

        const originalRequest = error.config;
        if (!originalRequest) {
          return Promise.reject(error);
        }

        // 423 Locked - a feature flag is disabled for this org. The named
        // flag goes off at once and stays off for a cooldown, so a stale
        // "on" from the flag endpoint cannot remount the page into another
        // 423. Only the 423 that closes a feature refetches; repeats while
        // it is closed just extend the cooldown, leaving the normal poll to
        // reopen it.
        if (error.response?.status === 423) {
          const featureKey = error.response.data?.feature as string | undefined;
          const shouldRefetchFlags = featureKey
            ? useFeatureFlagStore.getState().markFeatureLocked(featureKey)
            : true;
          if (shouldRefetchFlags) {
            queryClient.invalidateQueries({ queryKey: ["feature-flags"] });
          }
          return Promise.reject(error);
        }

        const accountRefusal = getAccountRefusal(error);
        if (accountRefusal) {
          endSession(accountRefusal);
          return Promise.reject(error);
        }

        if (
          error.response?.status === 401 &&
          !originalRequest._retry &&
          !originalRequest.url?.includes("refresh")
        ) {
          originalRequest._retry = true;
          // A failed refresh rejects here after refreshToken has logged it and ended the session.
          const refreshedSession = await this.refreshToken(
            readCorrelationId(originalRequest.headers),
          );
          const newToken =
            refreshedSession?.accessToken ?? refreshedSession?.token;
          if (newToken) {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            return this.axiosInstance(originalRequest);
          }
        }

        logHttpClientFailure(error);
        return Promise.reject(error);
      },
    );
  }

  /** The refresh carries the correlation ID of the call it is made for, when there is one. */
  private async refreshToken(
    correlationId?: string,
  ): Promise<AuthTokenResponse | null> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      endSession();
      return null;
    }

    this.refreshPromise = (async () => {
      try {
        this.isRefreshing = true;
        const refreshUrl = new URL(
          apiRoutes.mutation.auth.refresh,
          baseURL,
        ).toString();
        const response = await axios.post<AuthTokenResponse>(
          refreshUrl,
          { refreshToken },
          {
            headers: {
              "Content-Type": "application/json",
              [CORRELATION_ID_HEADER]: correlationId ?? generateCorrelationId(),
            },
            withCredentials: true,
            timeout: API_REQUEST_TIMEOUT_MS,
          },
        );

        const accessToken = response.data.accessToken ?? response.data.token;
        const newRefresh = response.data.refreshToken;
        const { expiresIn } = response.data;
        if (!accessToken || !newRefresh) {
          throw new Error("Refresh response is missing tokens.");
        }
        const expiresAt = Date.now() + normalizeExpiresInMs(expiresIn);

        if (typeof window !== "undefined") {
          tokenStorage.setTokens(accessToken, newRefresh);
          useAuthStore.getState().updateExpiresAt(expiresAt);
        }

        logger.info("Token refreshed successfully", {
          eventName: "auth.token_refreshed",
        });
        return response.data;
      } catch (error) {
        logger.error("Token refresh failed", {
          eventName: "auth.token_refresh.exception",
          error,
        });
        endSession(getAccountRefusal(error));
        throw error;
      } finally {
        this.isRefreshing = false;
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  public async refreshAccessToken(
    correlationId?: string,
  ): Promise<string | null> {
    const refreshedSession = await this.refreshToken(correlationId);
    return refreshedSession?.accessToken ?? refreshedSession?.token ?? null;
  }

  public async refreshAuthSession(): Promise<AuthTokenResponse | null> {
    return this.refreshToken();
  }

  private handleError(err: unknown): never {
    if (!err) {
      throw new Error("Unknown error occurred");
    }

    if (err instanceof AxiosError) {
      // Handle server down or network error
      if (!err.response) {
        logHttpClientFailure(err);
        reportApiNetworkIssue();
        throw unreachableError("Server is unreachable", err.config?.headers);
      }
    }

    throw err;
  }
  public async get<TResponse>(
    url: string,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      if (config?.params) {
        config.params = this.serializeQueryParams(config.params);
      }
      const response = await this.axiosInstance.get<TResponse>(url, config);
      return response;
    } catch (err) {
      return this.handleError(err);
    }
  }

  public async post<TResponse, TRequest = unknown>(
    url: string,
    data?: TRequest,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      const response = await this.axiosInstance.post<TResponse>(
        url,
        data,
        config,
      );
      return response;
    } catch (err) {
      return this.handleError(err);
    }
  }

  public async patch<TResponse, TRequest = unknown>(
    url: string,
    data?: TRequest,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      const response = await this.axiosInstance.patch<TResponse>(
        url,
        data,
        config,
      );
      return response;
    } catch (err) {
      return this.handleError(err);
    }
  }
  public async put<TResponse, TRequest = unknown>(
    url: string,
    data?: TRequest,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      const response = await this.axiosInstance.put<TResponse>(
        url,
        data,
        config,
      );
      return response;
    } catch (err) {
      return this.handleError(err);
    }
  }

  public async delete<TResponse, TRequest = unknown>(
    url: string,
    data?: TRequest,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      const response = await this.axiosInstance.delete<TResponse>(url, {
        ...config,
        data,
      });
      return response;
    } catch (err) {
      return this.handleError(err);
    }
  }
  private serializeQueryParams(
    params: Record<string, unknown>,
  ): Record<string, string> {
    const serialized: Record<string, string> = {};
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null) {
        continue;
      }

      serialized[key] =
        typeof value === "object" ? JSON.stringify(value) : String(value);
    }
    return serialized;
  }
}

class SupportApiClient {
  private axiosInstance: AxiosInstance;

  constructor() {
    this.axiosInstance = axios.create({
      baseURL: baseURL,
      withCredentials: false,
      timeout: API_REQUEST_TIMEOUT_MS,
    });

    this.axiosInstance.interceptors.request.use(
      (config) => {
        config.data = normalizeOrganizationIds(config.data);
        config.headers = config.headers ?? {};
        ensureCorrelationId(config.headers);

        const accessToken = tokenStorage.getAccessToken();
        if (accessToken) {
          config.headers.Authorization = `Bearer ${accessToken}`;
        }
        return config;
      },
      undefined,
      { synchronous: true },
    );

    this.axiosInstance.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (!error.response) {
          logHttpClientFailure(error);
          return Promise.reject(
            unreachableError("Service is unreachable", error.config?.headers),
          );
        }

        const originalRequest = error.config as
          (AxiosRequestConfig & { _retry?: boolean }) | undefined;
        if (!originalRequest) {
          return Promise.reject(error);
        }

        const accountRefusal = getAccountRefusal(error);
        if (accountRefusal) {
          endSession(accountRefusal);
          return Promise.reject(error);
        }

        if (error.response.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          const refreshedAccessToken = await apiClient.refreshAccessToken(
            readCorrelationId(originalRequest.headers),
          );

          if (refreshedAccessToken) {
            originalRequest.headers = {
              ...(originalRequest.headers ?? {}),
              Authorization: `Bearer ${refreshedAccessToken}`,
            };
            return this.axiosInstance(originalRequest);
          }
        }

        logHttpClientFailure(error);
        return Promise.reject(error);
      },
    );
  }

  async get<TResponse>(
    url: string,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      return await this.axiosInstance.get<TResponse>(url, config);
    } catch (error) {
      return this.handleError(error);
    }
  }

  async post<TResponse>(
    url: string,
    data?: unknown,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      return await this.axiosInstance.post<TResponse>(url, data, config);
    } catch (error) {
      return this.handleError(error);
    }
  }

  async put<TResponse>(
    url: string,
    data?: unknown,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      return await this.axiosInstance.put<TResponse>(url, data, config);
    } catch (error) {
      return this.handleError(error);
    }
  }

  async delete<TResponse>(
    url: string,
    data?: unknown,
    config?: AxiosRequestConfig,
  ): Promise<AxiosResponse<TResponse>> {
    try {
      return await this.axiosInstance.delete<TResponse>(url, {
        ...config,
        data,
      });
    } catch (error) {
      return this.handleError(error);
    }
  }

  private handleError(error: unknown): never {
    if (error instanceof AxiosError && !error.response) {
      throw new Error("Something went wrong!");
    }
    throw error;
  }
}

const supportApiClient = new SupportApiClient();
export { supportApiClient };

export const apiClient = ApiClient.getInstance();

export const publicApiClient = axios.create({
  baseURL: baseURL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: API_REQUEST_TIMEOUT_MS,
});

publicApiClient.interceptors.request.use(
  (config) => {
    config.data = normalizeOrganizationIds(config.data);
    config.headers = config.headers ?? {};
    ensureCorrelationId(config.headers);
    return config;
  },
  undefined,
  { synchronous: true },
);

publicApiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    logHttpClientFailure(error);
    return Promise.reject(error);
  },
);
