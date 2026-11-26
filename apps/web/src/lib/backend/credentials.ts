// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import {
  getCredentialReferenceProviderOptions,
  resolveCredentialProviderFromApiValue,
} from "@/lib/credential-providers";
import type {
  CreateCredentialReferenceInput,
  CredentialDeleteResponse,
  CredentialReference,
  CredentialReferenceList,
  CredentialReferenceType,
  CredentialUpdateResponse,
} from "@/types/cert-manager";

interface CredentialReferenceResponse {
  credentialXref: string;
  provider: string;
  type: CredentialReferenceType;
  description: string | null;
  status: string;
  lastError?: string | null;
  secretHandle: string | null;
  configJson: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

interface CredentialReferenceListResponse {
  items: CredentialReferenceResponse[];
  totalItems: number;
}

const toCredentialReference = (
  response: CredentialReferenceResponse,
): CredentialReference => {
  const providerOption = getCredentialReferenceProviderOptions(
    response.type,
  ).find((option) => option.apiValue === response.provider);

  return {
    credentialXref: response.credentialXref,
    provider: response.provider,
    providerKey:
      providerOption?.providerKey ||
      resolveCredentialProviderFromApiValue(response.provider),
    type: response.type,
    description: response.description ?? response.credentialXref,
    status: response.status,
    lastError: response.lastError ?? undefined,
    secretHandle: response.secretHandle,
    configJson: response.configJson ?? undefined,
    targetType: providerOption?.targetType,
    createdAt: response.createdAt ?? undefined,
    updatedAt: response.updatedAt ?? undefined,
  };
};

export const listCredentialReferences = async (
  type?: CredentialReferenceType,
): Promise<CredentialReferenceList> => {
  const response = await apiClient.get<CredentialReferenceListResponse>(
    apiRoutes.query.credentials.list,
    {
      params: type ? { type } : undefined,
    },
  );

  return {
    ...response.data,
    items: response.data.items.map(toCredentialReference),
  };
};

export const getCredentialReference = async (
  credentialXref: string,
): Promise<CredentialReference> => {
  const response = await apiClient.get<CredentialReferenceResponse>(
    apiRoutes.query.credentials.detail(credentialXref),
  );

  return toCredentialReference(response.data);
};

const createCredentialReference = async (
  path:
    | typeof apiRoutes.mutation.credentials.createDns
    | typeof apiRoutes.mutation.credentials.createDeployment
    | typeof apiRoutes.mutation.credentials.createDiscovery,
  payload: CreateCredentialReferenceInput,
): Promise<CredentialReference> => {
  const response = await apiClient.post<CredentialReferenceResponse>(
    path,
    payload,
  );
  return toCredentialReference(response.data);
};

export const createDnsCredentialReference = async (
  payload: CreateCredentialReferenceInput,
): Promise<CredentialReference> =>
  createCredentialReference(apiRoutes.mutation.credentials.createDns, payload);

export const createDeploymentCredentialReference = async (
  payload: CreateCredentialReferenceInput,
): Promise<CredentialReference> =>
  createCredentialReference(
    apiRoutes.mutation.credentials.createDeployment,
    payload,
  );

/** Read-only discovery credential, for example an AWS Organization. Never used to deploy. */
export const createDiscoveryCredentialReference = async (
  payload: CreateCredentialReferenceInput,
): Promise<CredentialReference> =>
  createCredentialReference(
    apiRoutes.mutation.credentials.createDiscovery,
    payload,
  );

export const updateCredentialReference = async (
  credentialXref: string,
  payload: {
    secretHandle?: string | null;
    credJson?: string | Record<string, unknown>;
    configJson?: string | Record<string, unknown>;
  },
): Promise<CredentialUpdateResponse> => {
  const response = await apiClient.put<CredentialUpdateResponse>(
    apiRoutes.mutation.credentials.update(credentialXref),
    payload,
  );
  return response.data;
};

export const deleteCredentialReference = async (
  credentialXref: string,
): Promise<CredentialDeleteResponse> => {
  const response = await apiClient.delete<CredentialDeleteResponse>(
    apiRoutes.mutation.credentials.delete(credentialXref),
  );
  return response.data;
};
