// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import { apiClient, apiRoutes } from "@/lib/api";
import type {
  CertificateAsyncResponse,
  CreateDeploymentInput,
  DeploymentCredentialConfigLookup,
  DeploymentQueryFilters,
  DeploymentQueryResult,
  DeploymentRecord,
  DeploymentSummary,
  UserDomainCertificateDeploymentSummary,
  UserDomainCertificateDeploymentSummaryPage,
} from "@/types/cert-manager";

const DEPLOYMENTS_PAGE_SIZE = 100;
const jsonObjectSchema = z.record(z.string(), z.unknown());

interface DeploymentApiRecord {
  id: number;
  requestId: string | null;
  correlationId: string | null;
  organizationId: number;
  userDomainCertId: number | null;
  certificateXref: string | null;
  domain: string | null;
  deploymentCredentialXref: string | null;
  targetType: string | null;
  flowType: string | null;
  status: string;
  wildcard: boolean | null;
  san: boolean | null;
  sanDomains: string[];
  validFrom: string | null;
  validTo: string | null;
  issuer: string | null;
  serialNumber: string | null;
  fingerprintSha256: string | null;
  targetResourceId: string | null;
  userMessage?: string;
  requestedAt: string | null;
  publishedAt: string | null;
  respondedAt: string | null;
  completedAt: string | null;
  source: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
}

interface DeploymentListApiResponse {
  mode: "list";
  items: DeploymentApiRecord[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
}

interface DeploymentSingleApiResponse {
  mode: "single";
  item: DeploymentApiRecord;
}

interface DeploymentSummaryApiResponse {
  mode: "summary";
  summary: DeploymentSummary;
}

type DeploymentQueryApiResponse =
  | DeploymentListApiResponse
  | DeploymentSingleApiResponse
  | DeploymentSummaryApiResponse;

interface DeploymentCredentialConfigApiResponse {
  certXref: string;
  domain: string;
  organizationId: number;
  userDomainCertId: number;
  deploymentCredentialXref: string;
  deploymentCredentialId: number;
  provider: string;
  config: string | null;
  createdAt: string;
  updatedAt: string;
}

interface CreateDeploymentApiRequest {
  deploymentCredentialXref: string;
  targetType: string;
  useDefault?: boolean;
  config?: CreateDeploymentInput["config"];
  targets?: CreateDeploymentInput["targets"];
}

const toDeploymentRecord = (
  deployment: DeploymentApiRecord,
): DeploymentRecord => ({
  id: deployment.id,
  requestId: deployment.requestId ?? undefined,
  correlationId: deployment.correlationId ?? undefined,
  organizationId: deployment.organizationId,
  userDomainCertId: deployment.userDomainCertId ?? undefined,
  certificateXref: deployment.certificateXref ?? undefined,
  domain: deployment.domain ?? undefined,
  deploymentCredentialXref: deployment.deploymentCredentialXref ?? undefined,
  targetType: deployment.targetType ?? undefined,
  flowType: deployment.flowType ?? undefined,
  status: deployment.status,
  wildcard: deployment.wildcard ?? undefined,
  san: deployment.san ?? undefined,
  sanDomains: deployment.sanDomains,
  validFrom: deployment.validFrom ?? undefined,
  validTo: deployment.validTo ?? undefined,
  issuer: deployment.issuer ?? undefined,
  serialNumber: deployment.serialNumber ?? undefined,
  fingerprintSha256: deployment.fingerprintSha256 ?? undefined,
  targetResourceId: deployment.targetResourceId ?? undefined,
  userMessage: deployment.userMessage,
  requestedAt: deployment.requestedAt ?? undefined,
  publishedAt: deployment.publishedAt ?? undefined,
  respondedAt: deployment.respondedAt ?? undefined,
  completedAt: deployment.completedAt ?? undefined,
  source: deployment.source ?? undefined,
  metadata: deployment.metadata ?? undefined,
  createdAt: deployment.createdAt,
  updatedAt: deployment.updatedAt,
});

const buildParams = (
  filters?: DeploymentQueryFilters,
): Record<string, string | number> | undefined => {
  if (!filters) {
    return undefined;
  }

  return Object.fromEntries(
    Object.entries(filters).flatMap(([key, value]) => {
      if (value == null || value === "") {
        return [];
      }
      return [
        [
          key === "userDomainCertificateId" ? "userdomaincertificateid" : key,
          value,
        ],
      ];
    }),
  ) as Record<string, string | number>;
};

export const queryDeployments = async (
  filters?: DeploymentQueryFilters,
  signal?: AbortSignal,
): Promise<DeploymentQueryResult> => {
  const response = await apiClient.get<DeploymentQueryApiResponse>(
    apiRoutes.query.deployment.list,
    { params: buildParams(filters), signal },
  );

  if (response.data.mode === "single") {
    return {
      mode: response.data.mode,
      items: [toDeploymentRecord(response.data.item)],
      totalItems: 1,
    };
  }

  if (response.data.mode === "summary") {
    return {
      mode: response.data.mode,
      items: [],
      summary: response.data.summary,
      totalItems: response.data.summary.total,
    };
  }

  return {
    mode: response.data.mode,
    items: response.data.items.map(toDeploymentRecord),
    page: response.data.page,
    size: response.data.size,
    totalItems: response.data.totalItems,
    totalPages: response.data.totalPages,
  };
};

export const getDeploymentSummary = async (): Promise<DeploymentSummary> => {
  const result = await queryDeployments({ view: "summary" });
  if (!result.summary) {
    throw new Error("Deployment summary response did not include summary data");
  }
  return result.summary;
};

export const listAllDeployments = async (
  filters?: DeploymentQueryFilters,
): Promise<DeploymentRecord[]> => {
  const pageSize = filters?.size ?? DEPLOYMENTS_PAGE_SIZE;
  const firstPage = await queryDeployments({
    ...filters,
    page: 0,
    size: pageSize,
  });

  const deployments = [...firstPage.items];
  for (let page = 1; page < (firstPage.totalPages ?? 1); page += 1) {
    const nextPage = await queryDeployments({
      ...filters,
      page,
      size: pageSize,
    });
    deployments.push(...nextPage.items);
  }
  return deployments;
};

export const getDeploymentByRequestId = async (
  requestId: string,
): Promise<DeploymentRecord | null> => {
  const result = await queryDeployments({ requestId, view: "list" });
  return result.items[0] ?? null;
};

export const queryUserDomainCertificateDeploymentSummaries = async (
  params?: {
    userDomainCertificateId?: string;
    domain?: string;
    page?: number;
    size?: number;
  },
  signal?: AbortSignal,
): Promise<UserDomainCertificateDeploymentSummaryPage> => {
  const response =
    await apiClient.get<UserDomainCertificateDeploymentSummaryPage>(
      apiRoutes.query.deployment.userDomainCertSummary,
      {
        signal,
        params: {
          ...(params?.userDomainCertificateId
            ? { userdomaincertificateid: params.userDomainCertificateId }
            : {}),
          ...(params?.domain ? { domain: params.domain } : {}),
          page: params?.page ?? 0,
          size: params?.size ?? DEPLOYMENTS_PAGE_SIZE,
        },
      },
    );
  return response.data;
};

export const listAllUserDomainCertificateDeploymentSummaries = async (params?: {
  userDomainCertificateId?: string;
  domain?: string;
  size?: number;
}): Promise<UserDomainCertificateDeploymentSummary[]> => {
  const pageSize = params?.size ?? DEPLOYMENTS_PAGE_SIZE;
  const firstPage = await queryUserDomainCertificateDeploymentSummaries({
    ...params,
    page: 0,
    size: pageSize,
  });

  const summaries = [...firstPage.items];
  for (let page = 1; page < firstPage.totalPages; page += 1) {
    const nextPage = await queryUserDomainCertificateDeploymentSummaries({
      ...params,
      page,
      size: pageSize,
    });
    summaries.push(...nextPage.items);
  }
  return summaries;
};

export const createDeployment = async (
  payload: CreateDeploymentInput,
): Promise<CertificateAsyncResponse> => {
  const requestPayload: CreateDeploymentApiRequest = {
    deploymentCredentialXref: payload.deploymentCredentialXref,
    targetType: payload.targetType,
    ...(payload.useDefault == null ? {} : { useDefault: payload.useDefault }),
    ...(payload.config ? { config: payload.config } : {}),
    ...(payload.targets ? { targets: payload.targets } : {}),
  };
  const response = await apiClient.post<CertificateAsyncResponse>(
    apiRoutes.mutation.certs.deploy(payload.certificateXref),
    requestPayload,
  );
  return response.data;
};

const parseConfigJson = (
  configJson: string | null,
): Record<string, unknown> | null => {
  if (!configJson?.trim()) {
    return null;
  }

  try {
    const parsed = jsonObjectSchema.safeParse(JSON.parse(configJson));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
};

export const getDeploymentCredentialConfig = async (
  certXref: string,
  deploymentCredentialXref: string,
): Promise<DeploymentCredentialConfigLookup> => {
  const response = await apiClient.get<DeploymentCredentialConfigApiResponse>(
    apiRoutes.query.deployment.credentialConfig,
    { params: { certXref, deploymentCredentialXref } },
  );

  return {
    ...response.data,
    config: parseConfigJson(response.data.config),
    targets: null,
  };
};
