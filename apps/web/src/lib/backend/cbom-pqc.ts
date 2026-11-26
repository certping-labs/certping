// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import type {
  CbomDocument,
  PqcAlgorithmGroup,
  PqcReadinessCertificate,
  PqcReadinessCertificatesParams,
  PqcReadinessReport,
} from "@/types/cbom-pqc";
import type { SpringPage } from "@/types/pagination";
import { ALGORITHM_LABELS } from "@/lib/cert-manager/pqc-algorithm-labels";

interface PqcReadinessApiSummary {
  total: number;
  pqcCompliant: number;
  deprecated2030: number;
  disallowed2035: number;
  unknown: number;
  highHndlRisk: number;
}

interface PqcReadinessApiCertificate {
  certificateXref: string;
  commonName: string;
  signatureAlgorithm: string | null;
  publicKeyAlgorithm: string | null;
  keySize: number | null;
  curve: string | null;
  quantumStatus: PqcReadinessCertificate["quantumStatus"];
  hndlRisk: PqcReadinessCertificate["hndlRisk"];
  deprecationYear: number | null;
  disallowedYear: number | null;
  complianceRef: string | null;
  remediationAdvice: string;
  source?: PqcReadinessCertificate["source"];
}

interface PqcReadinessApiResponse {
  summary: PqcReadinessApiSummary;
  algorithms: PqcAlgorithmGroup[];
}

export async function getCbomDocument(): Promise<CbomDocument> {
  const response = await apiClient.get<string>(apiRoutes.query.certs.cbom);
  const parsed = parseJsonOrReturnRaw(response.data);

  return {
    text:
      typeof parsed === "string"
        ? parsed
        : JSON.stringify(parsed, null, 2) || "{}",
  };
}

export async function getPqcReadinessReport(): Promise<PqcReadinessReport> {
  const response = await apiClient.get<PqcReadinessApiResponse>(
    apiRoutes.query.certs.pqcReadiness,
  );

  return {
    summary: {
      totalCertificates: response.data.summary.total,
      pqcCompliant: response.data.summary.pqcCompliant,
      deprecated2030: response.data.summary.deprecated2030,
      disallowed2035: response.data.summary.disallowed2035,
      unknown: response.data.summary.unknown,
      highHndlRisk: response.data.summary.highHndlRisk,
    },
    algorithms: response.data.algorithms,
  };
}

export async function getPqcReadinessCertificates(
  params: PqcReadinessCertificatesParams = {},
): Promise<SpringPage<PqcReadinessCertificate>> {
  const response = await apiClient.get<SpringPage<PqcReadinessApiCertificate>>(
    apiRoutes.query.certs.pqcReadinessCertificates,
    { params },
  );

  return {
    ...response.data,
    content: response.data.content.map(toPqcReadinessCertificate),
  };
}

function toPqcReadinessCertificate(
  certificate: PqcReadinessApiCertificate,
): PqcReadinessCertificate {
  const signatureAlgorithm = certificate.signatureAlgorithm ?? "";

  return {
    certificateId: null,
    certificateXref: certificate.certificateXref,
    commonName: certificate.commonName,
    keyAlgorithm:
      labelAlgorithm(certificate.publicKeyAlgorithm) ??
      inferKeyAlgorithm(signatureAlgorithm),
    keySize: certificate.keySize,
    curve: certificate.curve ?? "",
    signatureAlgorithm,
    quantumStatus: certificate.quantumStatus,
    hndlRisk: certificate.hndlRisk,
    deprecationYear: certificate.deprecationYear,
    disallowedYear: certificate.disallowedYear,
    complianceRef: certificate.complianceRef ?? "",
    remediationAdvice: certificate.remediationAdvice,
    source: certificate.source,
  };
}

function parseJsonOrReturnRaw(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function labelAlgorithm(publicKeyAlgorithm: string | null): string | null {
  if (!publicKeyAlgorithm) return null;
  return (
    ALGORITHM_LABELS[publicKeyAlgorithm.toUpperCase()] ?? publicKeyAlgorithm
  );
}

function inferKeyAlgorithm(signatureAlgorithm: string): string {
  const normalized = signatureAlgorithm.toUpperCase();

  if (normalized.includes("RSA")) {
    return "RSA";
  }

  if (normalized.includes("ECDSA")) {
    return "ECDSA";
  }

  if (normalized.includes("ED25519")) {
    return "Ed25519";
  }

  if (normalized.includes("ED448")) {
    return "Ed448";
  }

  if (normalized.includes("DSA")) {
    return "DSA";
  }

  return "";
}
