// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { ALGORITHM_LABELS } from "@/lib/cert-manager/pqc-algorithm-labels";
import type {
  PqcAlgorithmGroup,
  PqcReadinessSummary,
  QuantumStatus,
} from "@/types/cbom-pqc";

export interface AlgorithmGroup {
  algorithm: string;
  count: number;
  deprecationYear: number | null;
  disallowedYear: number | null;
  keyDetails: string;
  quantumStatus: QuantumStatus;
}

export interface StatusBreakdownItem {
  count: number;
  label: string;
  percentage: number;
  status: QuantumStatus;
}

const STATUS_PRIORITY: Record<QuantumStatus, number> = {
  DISALLOWED_2035: 3,
  DEPRECATED_2030: 2,
  UNKNOWN: 1,
  PQC_COMPLIANT: 0,
};

const DISPLAY_ORDER: Record<QuantumStatus, number> = {
  PQC_COMPLIANT: 0,
  DEPRECATED_2030: 1,
  DISALLOWED_2035: 2,
  UNKNOWN: 3,
};

export function buildAlgorithmGroups(
  algorithms: readonly PqcAlgorithmGroup[],
): AlgorithmGroup[] {
  const groups = new Map<string, AlgorithmGroup>();

  for (const entry of algorithms) {
    const algorithm = labelAlgorithm(entry.publicKeyAlgorithm);
    const existing = groups.get(algorithm);
    const keyDetail = formatKeyDetail(entry);

    if (!existing) {
      groups.set(algorithm, {
        algorithm,
        count: entry.certificates,
        deprecationYear: entry.deprecationYear,
        disallowedYear: entry.disallowedYear,
        keyDetails: keyDetail,
        quantumStatus: entry.quantumStatus,
      });
      continue;
    }

    existing.count += entry.certificates;
    existing.deprecationYear = earliestYear(
      existing.deprecationYear,
      entry.deprecationYear,
    );
    existing.disallowedYear = earliestYear(
      existing.disallowedYear,
      entry.disallowedYear,
    );
    existing.keyDetails = mergeKeyDetails(existing.keyDetails, keyDetail);

    if (
      STATUS_PRIORITY[entry.quantumStatus] >
      STATUS_PRIORITY[existing.quantumStatus]
    ) {
      existing.quantumStatus = entry.quantumStatus;
    }
  }

  return [...groups.values()].sort(
    (left, right) =>
      DISPLAY_ORDER[left.quantumStatus] - DISPLAY_ORDER[right.quantumStatus] ||
      right.count - left.count ||
      left.algorithm.localeCompare(right.algorithm),
  );
}

export function buildStatusBreakdown(
  summary: PqcReadinessSummary | undefined,
): StatusBreakdownItem[] {
  const total = summary?.totalCertificates ?? 0;
  const values: Array<[QuantumStatus, string, number]> = [
    ["PQC_COMPLIANT", "PQC compliant", summary?.pqcCompliant ?? 0],
    ["DEPRECATED_2030", "Deprecated 2030", summary?.deprecated2030 ?? 0],
    ["DISALLOWED_2035", "Disallowed 2035", summary?.disallowed2035 ?? 0],
    ["UNKNOWN", "Unknown", summary?.unknown ?? 0],
  ];

  return values.map(([status, label, count]) => ({
    count,
    label,
    percentage: total > 0 ? Math.round((count / total) * 100) : 0,
    status,
  }));
}

function earliestYear(
  left: number | null,
  right: number | null,
): number | null {
  if (left === null) return right;
  if (right === null) return left;
  return Math.min(left, right);
}

function labelAlgorithm(publicKeyAlgorithm: string | null): string {
  if (!publicKeyAlgorithm) return "Unknown algorithm";
  const normalized = publicKeyAlgorithm.toUpperCase();
  return ALGORITHM_LABELS[normalized] ?? publicKeyAlgorithm;
}

function formatKeyDetail(entry: PqcAlgorithmGroup): string {
  if (entry.curve) return entry.curve;
  if (entry.keySize) return `${entry.keySize}-bit`;
  return "Key metadata unavailable";
}

function mergeKeyDetails(current: string, next: string): string {
  if (current === next || current.includes(next)) return current;
  return `${current}, ${next}`;
}
