// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import {
  DISCOVERED_CERTS_PAGE_SIZE,
  type DiscoveredCert,
  type DiscoveredCertDetail,
  type DiscoveredCertPage,
  type DiscoveryFilters,
  type DiscoveryRunResponse,
} from "@/types/discovery";

const createDiscoveryParams = (
  filters: DiscoveryFilters,
): Record<string, string | number | boolean> => {
  const params: Record<string, string | number | boolean> = {
    page: filters.page ?? 0,
    size: filters.size ?? DISCOVERED_CERTS_PAGE_SIZE,
  };
  if (filters.domain) params.domain = filters.domain;
  if (filters.targetType) params.targetType = filters.targetType;
  if (filters.keyAlgorithm) params.keyAlgorithm = filters.keyAlgorithm;
  if (filters.certStatus) params.certStatus = filters.certStatus;
  if (filters.managed !== undefined) params.managed = filters.managed;
  if (filters.expiresWithinDays !== undefined) {
    params.expiresWithinDays = filters.expiresWithinDays;
  }
  return params;
};

export const listDiscoveredCerts = async (
  filters: DiscoveryFilters = {},
  signal?: AbortSignal,
): Promise<DiscoveredCertPage> => {
  const response = await apiClient.get<DiscoveredCertPage>(
    apiRoutes.query.discovery.certs,
    { params: createDiscoveryParams(filters), signal },
  );
  return response.data;
};

export const listAllDiscoveredCerts = async (
  filters: DiscoveryFilters = {},
): Promise<DiscoveredCert[]> => {
  const pageSize = filters.size ?? DISCOVERED_CERTS_PAGE_SIZE;
  const firstPage = await listDiscoveredCerts({
    ...filters,
    page: 0,
    size: pageSize,
  });

  if (firstPage.totalPages <= 1) {
    return firstPage.content;
  }

  const certificates = [...firstPage.content];
  for (let page = 1; page < firstPage.totalPages; page += 1) {
    const nextPage = await listDiscoveredCerts({
      ...filters,
      page,
      size: pageSize,
    });
    certificates.push(...nextPage.content);
  }
  return certificates;
};

export const getDiscoveredCertificate = async (
  id: number,
): Promise<DiscoveredCertDetail> => {
  const response = await apiClient.get<DiscoveredCertDetail>(
    apiRoutes.query.discovery.cert(id),
  );
  return response.data;
};

export const triggerDiscovery = async (
  targetType: string,
  credentialXref: string,
): Promise<DiscoveryRunResponse> => {
  const response = await apiClient.post<DiscoveryRunResponse>(
    apiRoutes.mutation.discovery.trigger,
    { targetType, credentialXref },
  );
  return response.data;
};

export const getDiscoveryConfigStatus = async (
  configId: number,
): Promise<DiscoveryRunResponse> => {
  const response = await apiClient.get<DiscoveryRunResponse>(
    apiRoutes.query.discovery.triggerConfig(configId),
  );
  return response.data;
};

export const listDiscoveryConfigs = async (): Promise<
  DiscoveryRunResponse[]
> => {
  const response = await apiClient.get<DiscoveryRunResponse[]>(
    apiRoutes.query.discovery.triggerConfigs,
  );
  return response.data;
};

export const rerunDiscoveryConfig = async (
  configId: number,
): Promise<DiscoveryRunResponse> => {
  const response = await apiClient.post<DiscoveryRunResponse>(
    apiRoutes.mutation.discovery.triggerConfig(configId),
  );
  return response.data;
};

export const rerunAllDiscoveryConfigs = async (): Promise<
  DiscoveryRunResponse[]
> => {
  const response = await apiClient.post<DiscoveryRunResponse[]>(
    apiRoutes.mutation.discovery.triggerAll,
  );
  return response.data;
};

export const deleteDiscoveryConfig = async (
  configId: number,
): Promise<void> => {
  await apiClient.delete(apiRoutes.mutation.discovery.triggerConfig(configId));
};
