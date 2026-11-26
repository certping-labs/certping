// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getCertificateManagementLabel } from "@/lib/certificate-management";
import {
  isFailedCertificateStatus,
  isNeedsActionCertificateStatus,
  isIssuanceFailedCertificateStatus,
  isPendingCertificateStatus,
  isServingCertificateStatus,
  normalizeCertificateStatus,
} from "@/lib/cert-manager/certificate-status";
import type { SSLCertificateListItem } from "@/types/ssl";

export interface CertificateDashboardMetrics {
  total: number;
  active: number;
  expiring: number;
  pending: number;
  failed: number;
}

export function computeCertificateDashboardMetrics(
  certificates: SSLCertificateListItem[],
  now: Date,
): CertificateDashboardMetrics {
  let active = 0;
  let pending = 0;
  let expiring = 0;
  let failed = 0;

  for (const certificate of certificates) {
    if (isServingCertificateStatus(certificate.status)) {
      active += 1;
      if (!certificate.validTo) {
        continue;
      }

      const validTo = new Date(certificate.validTo);
      const remainingDays = Math.ceil(
        (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
      );
      if (remainingDays > 0 && remainingDays <= 30) {
        expiring += 1;
      }
      continue;
    }

    if (
      isPendingCertificateStatus(certificate.status) ||
      isNeedsActionCertificateStatus(certificate.status)
    ) {
      pending += 1;
    }
    // Issuance failures only: the count must match the rows ?status=FAILED shows.
    if (isIssuanceFailedCertificateStatus(certificate.status)) {
      failed += 1;
    }
  }

  return {
    total: certificates.length,
    active,
    expiring,
    pending,
    failed,
  };
}

export function getCertificateProviderOptions(
  certificates: SSLCertificateListItem[],
): string[] {
  return Array.from(
    new Set(
      certificates
        .map((certificate) => certificate.caProvider?.trim())
        .filter((provider): provider is string => Boolean(provider)),
    ),
  ).sort((left, right) => left.localeCompare(right));
}

/**
 * Distinct issuers in the inventory, sorted, for the "which certificates chain to X" filter: the
 * question a CA incident or a root-program removal asks first.
 */
export function getCertificateIssuerOptions(
  certificates: SSLCertificateListItem[],
): string[] {
  return Array.from(
    new Set(
      certificates
        .map((certificate) => certificate.issuer?.trim())
        .filter((issuer): issuer is string => Boolean(issuer)),
    ),
  ).sort((left, right) => left.localeCompare(right));
}

export interface CertificateCardFilterInput {
  certificates: SSLCertificateListItem[];
  searchTerm: string;
  statusFilter: string;
  providerFilter: string;
  /** An issuer from {@link getCertificateIssuerOptions}; empty or "all" means every issuer. */
  issuerFilter?: string;
}

export function filterCertificatesForCardView({
  certificates,
  searchTerm,
  statusFilter,
  providerFilter,
  issuerFilter = "all",
}: CertificateCardFilterInput): SSLCertificateListItem[] {
  const normalizedSearch = searchTerm.trim().toLowerCase();
  const normalizedStatusFilter = statusFilter.trim();
  const normalizedProviderFilter = providerFilter.trim();
  const normalizedIssuerFilter = issuerFilter.trim() || "all";

  return certificates.filter((certificate) => {
    const matchesSearch =
      normalizedSearch.length === 0 ||
      certificate.domain.toLowerCase().includes(normalizedSearch) ||
      certificate.certificateXref?.toLowerCase().includes(normalizedSearch) ||
      certificate.caProvider?.toLowerCase().includes(normalizedSearch) ||
      certificate.issuer?.toLowerCase().includes(normalizedSearch) ||
      getCertificateManagementLabel(certificate.managementState || "manual")
        .toLowerCase()
        .includes(normalizedSearch);

    const matchesStatus =
      normalizedStatusFilter === "all" ||
      certificate.status === normalizedStatusFilter;
    const matchesProvider =
      normalizedProviderFilter === "all" ||
      certificate.caProvider === normalizedProviderFilter;

    const matchesIssuer =
      normalizedIssuerFilter === "all" ||
      certificate.issuer?.trim() === normalizedIssuerFilter;

    return matchesSearch && matchesStatus && matchesProvider && matchesIssuer;
  });
}

/**
 * Table filter id -> URL parameter. `?renewal=` keeps its name so existing links
 * (overview next steps, expiry alerts) still open the expiry filter.
 */
const TABLE_FILTER_URL_PARAMS = {
  status: "status",
  caProvider: "provider",
  issuer: "issuer",
  managementState: "managementState",
  renewalWindow: "renewal",
} as const;

type CertificateTableFilterId = keyof typeof TABLE_FILTER_URL_PARAMS;

const TABLE_FILTER_IDS = Object.keys(
  TABLE_FILTER_URL_PARAMS,
) as CertificateTableFilterId[];

/** The table filters a URL asks for; empty and "all" values mean no filter. */
export function readCertificateTableFilters(
  searchParams: Pick<URLSearchParams, "get">,
): Record<string, string> {
  const filters: Record<string, string> = {};
  for (const id of TABLE_FILTER_IDS) {
    const value = searchParams.get(TABLE_FILTER_URL_PARAMS[id])?.trim();
    if (value && value !== "all") {
      filters[id] = value;
    }
  }
  return filters;
}

/** True when both describe the same table filters, ignoring key order. */
export function areCertificateTableFiltersEqual(
  left: Record<string, string>,
  right: Record<string, string>,
): boolean {
  return TABLE_FILTER_IDS.every((id) => (left[id] ?? "") === (right[id] ?? ""));
}

/** The query string with the table filters replaced by `filterState`; other params (search) stay. */
export function buildCertificateDashboardQueryString({
  currentSearchParams,
  filterState,
}: {
  currentSearchParams: URLSearchParams;
  filterState: Record<string, string>;
}): string {
  const nextParams = new URLSearchParams(currentSearchParams.toString());
  for (const id of TABLE_FILTER_IDS) {
    const param = TABLE_FILTER_URL_PARAMS[id];
    nextParams.delete(param);
    if (filterState[id]) {
      nextParams.set(param, filterState[id]);
    }
  }
  return nextParams.toString();
}

const DAY_MS = 1000 * 60 * 60 * 24;

function attentionRank(
  certificate: SSLCertificateListItem,
  now: number,
): [number, number] {
  const status = normalizeCertificateStatus(certificate.status);
  if (isFailedCertificateStatus(status)) {
    return [0, 0];
  }
  if (isNeedsActionCertificateStatus(status)) {
    return [1, 0];
  }
  if (status === "EXPIRED") {
    return [2, 0];
  }
  if (isServingCertificateStatus(status) && certificate.validTo) {
    const expiresAt = new Date(certificate.validTo).getTime();
    if (Number.isFinite(expiresAt) && expiresAt - now <= 30 * DAY_MS) {
      return [2, expiresAt];
    }
  }
  return [3, 0];
}

export function sortCertificatesByAttention(
  certificates: SSLCertificateListItem[],
  now: Date,
): SSLCertificateListItem[] {
  const nowMs = now.getTime();
  return certificates
    .map((certificate, index) => ({
      certificate,
      index,
      rank: attentionRank(certificate, nowMs),
    }))
    .sort(
      (left, right) =>
        left.rank[0] - right.rank[0] ||
        left.rank[1] - right.rank[1] ||
        left.index - right.index,
    )
    .map((entry) => entry.certificate);
}
