// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { parseKeyCustody } from "@/lib/cert-manager/key-custody";
import { apiClient, apiRoutes } from "@/lib/api";
import { AxiosError } from "axios";
import type {
  CertificateAsyncResponse,
  CertificateHistoryItem,
  CertificateHistoryPage,
  CertificateListPage,
  CertificateTxtRecord,
  ExpiringCertificateRow,
  ExpiringCertificatesSlice,
  ConvertToAutomatedInput,
  ConvertToAutomatedResponse,
  IssueCertificateInput,
  IssueManualCertificateInput,
  ManagedCertificateSummary,
  ManagedCertificateStatus,
} from "@/types/cert-manager";
import type { SSLCertificateDetails } from "@/types/ssl";
import {
  parseCertificateExportAvailability,
  withExportAvailability,
} from "@/lib/cert-manager/certificate-export-availability";
import {
  getCertificateManagementState,
  getPrimaryDnsConfigXref,
} from "@/lib/certificate-management";

const CERT_PAGE_SIZE = 100;
const CERTIFICATE_LIST_REQUEST_TIMEOUT_MS = 120_000;

/** Matches the server's `ExpiringCertsConstants` for GET /api/v1/certs/expiring. */
const EXPIRING_CERTS_DEFAULT_WITHIN_DAYS = 7;
const EXPIRING_CERTS_DEFAULT_PAGE = 0;
const EXPIRING_CERTS_DEFAULT_PAGE_SIZE = 20;
const EXPIRING_CERTS_MAX_PAGE_SIZE = 100;

interface CertificateSummaryResponse {
  certificateXref?: string | null;
  userDomainCertId?: number | null;
  domain?: string | null;
  caProvider?: string | null;
  status?: ManagedCertificateStatus | null;
  wildcard?: boolean;
  san?: boolean;
  sanDomains?: string[];
  dnsConfigXref?: Record<string, string>;
  dnsCredentialKvPath?: string | null;
  deploymentCredentialXrefs?: string[];
  deploymentCredentialKvPaths?: string[];
  validFrom?: string | null;
  validTo?: string | null;
  certType?: string;
  signatureAlgorithm?: string;
  publicKeyAlgorithm?: string;
  keySize?: number;
  createdAt?: string;
  updatedAt?: string;
  issuer?: string;
  serialNumber?: string;
  fingerprintSha256?: string;
  orderId?: string;
  exportAvailable?: boolean | null;
  keyCustody?: string | null;
  /** The detail DTO's export block; list rows carry `exportAvailable` instead. */
  export?: unknown;
}

interface CertificatePageResponse {
  items: CertificateSummaryResponse[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
}

interface CertificateTxtRecordsResponse {
  txtRecords: CertificateTxtRecord[];
}

interface CertificateHistoryPageResponse extends Omit<
  CertificatePageResponse,
  "items"
> {
  items: CertificateSummaryResponse[];
}

const toManagedCertificate = (
  response: CertificateSummaryResponse,
): ManagedCertificateSummary => {
  const certificateXref = response.certificateXref?.trim() || "unknown-cert";
  const deploymentCredentialXrefs = response.deploymentCredentialXrefs ?? [];
  const dnsConfigXref = response.dnsConfigXref ?? {};
  const status = response.status?.trim().toUpperCase() || "UNKNOWN";

  const { export: exportBlock, ...summary } = response;

  return {
    ...summary,
    certificateXref,
    domain: response.domain?.trim() || certificateXref,
    caProvider: response.caProvider?.trim() || undefined,
    status,
    userDomainCertId:
      response.userDomainCertId == null
        ? undefined
        : String(response.userDomainCertId),
    rawStatus: status,
    sanDomains: response.sanDomains ?? [],
    dnsConfigXref: getPrimaryDnsConfigXref(dnsConfigXref, response.domain),
    deploymentCredentialXrefs,
    managementState: getCertificateManagementState({
      dnsConfigXref,
      deploymentCredentialXrefs,
    }),
    deploymentCredentialKvPaths: response.deploymentCredentialKvPaths ?? [],
    exportAvailable:
      response.exportAvailable ??
      parseCertificateExportAvailability(exportBlock)?.available === true,
    keyCustody: parseKeyCustody(response.keyCustody),
  };
};

export const listCertificatesPage = async (params?: {
  page?: number;
  size?: number;
  status?: string;
  domain?: string;
  signal?: AbortSignal;
}): Promise<CertificateListPage> => {
  const response = await apiClient.get<CertificatePageResponse>(
    apiRoutes.query.certs.list,
    {
      params: {
        page: params?.page ?? 0,
        size: params?.size ?? CERT_PAGE_SIZE,
        ...(params?.status ? { status: params.status } : {}),
        ...(params?.domain ? { domain: params.domain } : {}),
      },
      ...(params?.signal ? { signal: params.signal } : {}),
      timeout: CERTIFICATE_LIST_REQUEST_TIMEOUT_MS,
    },
  );

  return {
    ...response.data,
    items: response.data.items.map(toManagedCertificate),
  };
};

export const listAllCertificates = async (): Promise<
  ManagedCertificateSummary[]
> => {
  const firstPage = await listCertificatesPage({
    page: 0,
    size: CERT_PAGE_SIZE,
  });
  if (firstPage.totalPages <= 1) {
    return firstPage.items;
  }

  const certificates = [...firstPage.items];
  for (let page = 1; page < firstPage.totalPages; page += 1) {
    const nextPage = await listCertificatesPage({
      page,
      size: CERT_PAGE_SIZE,
    });
    certificates.push(...nextPage.items);
  }
  return certificates;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const readTrimmedString = (value: unknown): string =>
  typeof value === "string" ? value.trim() : "";

const readFiniteNumber = (value: unknown, fallback: number): number =>
  typeof value === "number" && Number.isFinite(value) ? value : fallback;

const resolveExpiringPageSize = (size: number | undefined): number => {
  if (size == null || !Number.isFinite(size) || size < 1) {
    return EXPIRING_CERTS_DEFAULT_PAGE_SIZE;
  }
  return Math.min(Math.trunc(size), EXPIRING_CERTS_MAX_PAGE_SIZE);
};

/**
 * Copies only the expiring-certificate projection. Extra response keys (credential
 * xrefs, KV paths, secret handles) are intentionally not forwarded.
 */
const toExpiringCertificateRow = (
  value: unknown,
): ExpiringCertificateRow | null => {
  if (!isRecord(value)) {
    return null;
  }

  const certificateXref = readTrimmedString(value.certificateXref);
  if (!certificateXref) {
    return null;
  }

  const domain = readTrimmedString(value.domain) || certificateXref;
  const status = readTrimmedString(value.status).toUpperCase() || "UNKNOWN";
  const caProvider = readTrimmedString(value.caProvider) || undefined;
  const validTo = readTrimmedString(value.validTo) || null;

  return {
    domain,
    certificateXref,
    validTo,
    status,
    caProvider,
  };
};

const toExpiringCertificatesSlice = (
  value: unknown,
  requested: { withinDays: number; page: number; size: number },
): ExpiringCertificatesSlice => {
  const body = isRecord(value) ? value : {};
  const rawItems = Array.isArray(body.items) ? body.items : [];

  return {
    items: rawItems.flatMap((item) => {
      const row = toExpiringCertificateRow(item);
      return row ? [row] : [];
    }),
    page: readFiniteNumber(body.page, requested.page),
    size: readFiniteNumber(body.size, requested.size),
    hasNext: typeof body.hasNext === "boolean" ? body.hasNext : false,
    withinDays: readFiniteNumber(body.withinDays, requested.withinDays),
  };
};

/**
 * ACTIVE certificates whose `validTo` falls in the UTC window
 * `[now, now+withinDays]`.
 *
 * Defaults match the service: `withinDays` 7 (valid range 1..90, enforced
 * server-side), `page` 0, `size` 20. Requested `size` above 100 is clamped
 * to 100 before the call. The body is a slice: `items`, `page`, `size`,
 * `hasNext`, `withinDays` — no total count.
 */
export const listExpiringCertificates = async (params?: {
  withinDays?: number;
  page?: number;
  size?: number;
  signal?: AbortSignal;
}): Promise<ExpiringCertificatesSlice> => {
  const query = {
    withinDays: params?.withinDays ?? EXPIRING_CERTS_DEFAULT_WITHIN_DAYS,
    page: params?.page ?? EXPIRING_CERTS_DEFAULT_PAGE,
    size: resolveExpiringPageSize(params?.size),
  };
  const response = await apiClient.get<unknown>(
    apiRoutes.query.certs.expiring,
    {
      params: query,
      ...(params?.signal ? { signal: params.signal } : {}),
    },
  );

  return toExpiringCertificatesSlice(response.data, query);
};

/** Returns the certificate identified by its backend certificate xref. */
export const getCertificateByXref = async (
  certificateXref: string,
): Promise<ManagedCertificateSummary> => {
  const response = await apiClient.get<CertificateSummaryResponse>(
    apiRoutes.query.certs.detail(certificateXref),
  );
  return toManagedCertificate(response.data);
};

export const getCertificateDetail = async (
  certificateXref: string,
): Promise<ManagedCertificateSummary> => {
  try {
    return await getCertificateByXref(certificateXref);
  } catch (error) {
    const isNotFound =
      error instanceof AxiosError && error.response?.status === 404;

    if (!isNotFound) {
      throw error;
    }

    const candidates = await listAllCertificates();
    const normalizedIdentifier = certificateXref.toLowerCase();
    const match = candidates.find(
      (item) =>
        item.certificateXref.toLowerCase() === normalizedIdentifier ||
        item.domain.toLowerCase() === normalizedIdentifier,
    );

    if (!match) {
      throw error;
    }

    try {
      return await getCertificateByXref(match.certificateXref);
    } catch (detailError) {
      const detailNotFound =
        detailError instanceof AxiosError &&
        detailError.response?.status === 404;

      if (!detailNotFound) {
        throw detailError;
      }

      // Pending or failed certificates may only be available via the list API.
      return match;
    }
  }
};

export const getCertificateDetailsRecord = async (
  certificateXref: string,
): Promise<SSLCertificateDetails> => {
  try {
    const response = await apiClient.get<SSLCertificateDetails>(
      apiRoutes.query.certs.detail(certificateXref),
    );

    return withExportAvailability(response.data);
  } catch (error) {
    const isNotFound =
      error instanceof AxiosError && error.response?.status === 404;

    if (!isNotFound) {
      throw error;
    }

    const candidates = await listAllCertificates();
    const normalizedIdentifier = certificateXref.toLowerCase();
    const match = candidates.find(
      (item) =>
        item.certificateXref.toLowerCase() === normalizedIdentifier ||
        item.domain.toLowerCase() === normalizedIdentifier,
    );

    if (!match) {
      throw error;
    }

    try {
      const response = await apiClient.get<SSLCertificateDetails>(
        apiRoutes.query.certs.detail(match.certificateXref),
      );
      return withExportAvailability(response.data);
    } catch (detailError) {
      const detailNotFound =
        detailError instanceof AxiosError &&
        detailError.response?.status === 404;

      if (!detailNotFound) {
        throw detailError;
      }

      return {
        ...match,
        validFrom: match.validFrom || undefined,
        validTo: match.validTo || undefined,
      };
    }
  }
};

export const issueCertificate = async (
  payload: IssueCertificateInput,
): Promise<CertificateAsyncResponse> => {
  const response = await apiClient.post<CertificateAsyncResponse>(
    apiRoutes.mutation.certs.issue,
    payload,
  );
  return response.data;
};

export const issueManualCertificate = async (
  payload: IssueManualCertificateInput,
): Promise<CertificateAsyncResponse> => {
  const response = await apiClient.post<CertificateAsyncResponse>(
    apiRoutes.mutation.certs.issueManual,
    payload,
  );
  return response.data;
};

export const convertCertificateToAutomated = async (
  certificateXref: string,
  payload: ConvertToAutomatedInput,
): Promise<ConvertToAutomatedResponse> => {
  const response = await apiClient.post<ConvertToAutomatedResponse>(
    apiRoutes.mutation.certs.convertToAutomated(certificateXref),
    payload,
  );
  return response.data;
};

export const renewCertificate = async (
  certificateXref: string,
  payload?: { deploymentTargets?: string[] },
): Promise<CertificateAsyncResponse> => {
  const response = await apiClient.post<CertificateAsyncResponse>(
    apiRoutes.mutation.certs.renew(certificateXref),
    payload,
  );
  return response.data;
};

export const revokeCertificate = async (
  certificateXref: string,
  payload?: { reason?: string },
): Promise<CertificateAsyncResponse> => {
  const response = await apiClient.post<CertificateAsyncResponse>(
    apiRoutes.mutation.certs.revoke(certificateXref),
    payload,
  );
  return response.data;
};

export const deleteCertificate = async (
  userDomainCertId: string | number,
): Promise<void> => {
  await apiClient.delete(apiRoutes.mutation.certs.delete(userDomainCertId));
};

export const getCertificateTxtRecords = async (
  certificateXref: string,
): Promise<CertificateTxtRecord[]> => {
  const response = await apiClient.get<CertificateTxtRecordsResponse>(
    apiRoutes.query.certs.txtRecords(certificateXref),
  );
  return response.data.txtRecords;
};

export const validateCertificateDns = async (
  certificateXref: string,
): Promise<void> => {
  await apiClient.post(apiRoutes.mutation.certs.validateDns(certificateXref));
};

const toCertificateHistoryItem = (
  response: CertificateSummaryResponse,
): CertificateHistoryItem => {
  const certificateXref = response.certificateXref?.trim() || "unknown-cert";
  return {
    ...response,
    certificateXref,
    domain: response.domain?.trim() || certificateXref,
    caProvider: response.caProvider?.trim() || undefined,
    status: response.status?.trim().toUpperCase() || "UNKNOWN",
    userDomainCertId:
      response.userDomainCertId == null
        ? ""
        : String(response.userDomainCertId),
    issuer: response.issuer ?? null,
    sanDomains: response.sanDomains ?? [],
    dnsConfigXref: response.dnsConfigXref ?? null,
    deploymentCredentialXrefs: response.deploymentCredentialXrefs ?? [],
    dnsCredentialKvPath: response.dnsCredentialKvPath ?? null,
    deploymentCredentialKvPaths: response.deploymentCredentialKvPaths ?? [],
    validFrom: response.validFrom ?? null,
    validTo: response.validTo ?? null,
  };
};

export const getCertificateHistory = async (params: {
  udcId: string;
  page?: number;
  size?: number;
}): Promise<CertificateHistoryPage> => {
  const response = await apiClient.get<CertificateHistoryPageResponse>(
    apiRoutes.query.certs.history,
    {
      params: {
        udc_id: params.udcId,
        page: params.page ?? 0,
        size: params.size ?? 20,
      },
    },
  );

  return {
    ...response.data,
    items: response.data.items.map(toCertificateHistoryItem),
  };
};
