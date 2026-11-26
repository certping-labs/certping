// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import type {
  AuthTokenResponse,
  MessageResponse,
  Organization,
} from "@/types/auth";

interface OrganizationPurgeResult {
  organizationId: number;
  retentionDays: number;
  totalHardDeleted: number;
  details: Record<string, number>;
}

interface OrganizationRetentionApiResponse {
  organizationId: number;
  overrideDays: number | "null";
  effectiveDays: number;
  globalDays: number;
}

export const getOrganizationIdValue = (organization: Organization): string =>
  String(organization.id);

export const listOrganizations = async (): Promise<Organization[]> => {
  const response = await apiClient.get<Organization[]>(
    apiRoutes.query.organization.list,
  );
  return response.data;
};

export const getOrganizationById = async (
  organizationId: string,
): Promise<Organization> => {
  const response = await apiClient.get<Organization>(
    apiRoutes.query.organization.organizationById(organizationId),
  );
  return response.data;
};

export const getOrganizationBySlug = async (
  slug: string,
): Promise<Organization> => {
  const response = await apiClient.get<Organization>(
    apiRoutes.query.organization.organizationBySlug(slug),
  );
  return response.data;
};

export const createOrganization = async (payload: {
  name: string;
  domain: string;
}): Promise<Organization> => {
  const response = await apiClient.post<Organization>(
    apiRoutes.mutation.organization.create,
    payload,
  );
  return response.data;
};

export const updateOrganization = async (
  organizationId: string,
  payload: {
    name: string;
    domain: string;
    active?: boolean;
  },
): Promise<Organization> => {
  const response = await apiClient.put<Organization>(
    apiRoutes.mutation.organization.update(organizationId),
    payload,
  );
  return response.data;
};

/**
 * Super admin: makes `organizationId` the organization they work in. The answer carries new
 * tokens for it; the old refresh token names the old organization and no longer refreshes.
 */
export const setWorkingOrganization = async (
  organizationId: number | string,
): Promise<AuthTokenResponse> => {
  const response = await apiClient.put<AuthTokenResponse>(
    apiRoutes.mutation.admin.workingOrganization,
    {
      organizationId: Number(organizationId),
    },
  );
  return response.data;
};

export const deleteOrganization = async (
  organizationId: string,
): Promise<MessageResponse> => {
  const response = await apiClient.delete<MessageResponse>(
    apiRoutes.mutation.organization.delete(organizationId),
  );
  return response.data;
};

export const purgeOrgSoftDeleted = async (
  orgId: string | number,
): Promise<OrganizationPurgeResult> => {
  const response = await apiClient.post<OrganizationPurgeResult>(
    apiRoutes.mutation.organization.purgeSoftDeleted(orgId),
  );
  return response.data;
};

export const getOrgRetentionSettings = async (
  orgId: string | number,
): Promise<{
  overrideDays: number | null;
  effectiveDays: number;
  globalDays: number;
}> => {
  const response = await apiClient.get<OrganizationRetentionApiResponse>(
    apiRoutes.query.organization.retentionSettings(orgId),
  );
  return {
    overrideDays:
      response.data.overrideDays === "null" ? null : response.data.overrideDays,
    effectiveDays: response.data.effectiveDays,
    globalDays: response.data.globalDays,
  };
};

export const setOrgRetentionSettings = async (
  orgId: string | number,
  days: number | null,
): Promise<void> => {
  await apiClient.put(
    apiRoutes.mutation.organization.retentionSettings(orgId),
    { days: days === null ? "null" : days },
  );
};

export const getGlobalRetentionSettings = async (): Promise<{
  globalRetentionDays: number;
}> => {
  const response = await apiClient.get<{ globalRetentionDays: number }>(
    apiRoutes.mutation.admin.globalRetentionSettings,
  );
  return response.data;
};

export const setGlobalRetentionSettings = async (
  days: number,
): Promise<void> => {
  await apiClient.put(apiRoutes.mutation.admin.globalRetentionSettings, {
    days,
  });
};
