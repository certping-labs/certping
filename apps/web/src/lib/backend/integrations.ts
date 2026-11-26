// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiRoutes, supportApiClient } from "@/lib/api";
import type {
  CreateIntegrationPayload,
  CreatePagerDutyIncidentPayload,
  CreatePagerDutyIncidentResponse,
  CreateServiceNowIncidentPayload,
  CreateServiceNowIncidentResponse,
  Integration,
  IncidentHistoryPage,
  UpdateIntegrationPayload,
} from "@/types/integrations";

const stripEmptyFields = <T extends object>(payload: T): T => {
  return Object.fromEntries(
    Object.entries(payload as Record<string, unknown>).filter(([, value]) => {
      if (typeof value === "string") {
        return value.trim().length > 0;
      }
      return value !== undefined && value !== null;
    }),
  ) as T;
};

export const listIntegrations = async (): Promise<Integration[]> => {
  const response = await supportApiClient.get<Integration[]>(
    apiRoutes.query.integrations.list,
  );
  return response.data;
};

export const getIntegration = async (
  integrationId: number | string,
): Promise<Integration> => {
  const response = await supportApiClient.get<Integration>(
    apiRoutes.query.integrations.detail(integrationId),
  );
  return response.data;
};

export const createIntegration = async (
  payload: CreateIntegrationPayload,
): Promise<Integration> => {
  const response = await supportApiClient.post<Integration>(
    apiRoutes.mutation.integrations.create,
    stripEmptyFields(payload),
  );
  return response.data;
};

export const updateIntegration = async (
  integrationId: number | string,
  payload: UpdateIntegrationPayload,
): Promise<Integration> => {
  const response = await supportApiClient.put<Integration>(
    apiRoutes.mutation.integrations.update(integrationId),
    stripEmptyFields(payload),
  );
  return response.data;
};

export const deleteIntegration = async (
  integrationId: number | string,
): Promise<void> => {
  await supportApiClient.delete(
    apiRoutes.mutation.integrations.delete(integrationId),
  );
};

export const listIncidentHistory = async (params?: {
  page?: number;
  size?: number;
}): Promise<IncidentHistoryPage> => {
  const response = await supportApiClient.get<IncidentHistoryPage>(
    apiRoutes.query.supportIncidents.list,
    {
      params: {
        page: params?.page ?? 0,
        size: params?.size ?? 50,
      },
    },
  );
  return response.data;
};

export const createPagerDutyIncident = async (
  payload: CreatePagerDutyIncidentPayload,
): Promise<CreatePagerDutyIncidentResponse> => {
  const response = await supportApiClient.post<CreatePagerDutyIncidentResponse>(
    apiRoutes.mutation.supportIncidents.createPagerDuty,
    stripEmptyFields(payload),
  );
  return response.data;
};

export const createServiceNowIncident = async (
  payload: CreateServiceNowIncidentPayload,
): Promise<CreateServiceNowIncidentResponse> => {
  const response =
    await supportApiClient.post<CreateServiceNowIncidentResponse>(
      apiRoutes.mutation.supportIncidents.createServiceNow,
      stripEmptyFields(payload),
    );
  return response.data;
};
