// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export type QuantumStatus =
  "PQC_COMPLIANT" | "DEPRECATED_2030" | "DISALLOWED_2035" | "UNKNOWN";

export type HndlRisk = "HIGH" | "LOW" | "UNKNOWN";

export interface CbomDocument {
  text: string;
}

export interface PqcReadinessSummary {
  totalCertificates: number;
  pqcCompliant: number;
  deprecated2030: number;
  disallowed2035: number;
  unknown: number;
  highHndlRisk: number;
}

export interface PqcReadinessCertificate {
  certificateId: number | null;
  certificateXref: string;
  commonName: string;
  keyAlgorithm: string;
  keySize: number | null;
  curve: string;
  signatureAlgorithm: string;
  quantumStatus: QuantumStatus;
  hndlRisk: HndlRisk;
  deprecationYear: number | null;
  disallowedYear: number | null;
  complianceRef: string;
  remediationAdvice: string;
  /** DISCOVERED: found by a discovery scan, not managed by CertPing; certificateXref is where it was found. */
  source?: "MANAGED" | "DISCOVERED";
}

export interface PqcAlgorithmGroup {
  publicKeyAlgorithm: string | null;
  keySize: number | null;
  curve: string | null;
  quantumStatus: QuantumStatus;
  deprecationYear: number | null;
  disallowedYear: number | null;
  certificates: number;
}

export interface PqcReadinessReport {
  summary: PqcReadinessSummary;
  algorithms: PqcAlgorithmGroup[];
}

export interface PqcReadinessCertificatesParams {
  quantumStatus?: QuantumStatus;
  page?: number;
  size?: number;
}
