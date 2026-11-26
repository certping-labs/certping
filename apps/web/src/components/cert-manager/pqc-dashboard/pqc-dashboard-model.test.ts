// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  buildAlgorithmGroups,
  buildStatusBreakdown,
} from "@/components/cert-manager/pqc-dashboard/pqc-dashboard-model";
import type { PqcAlgorithmGroup } from "@/types/cbom-pqc";

const rsa4096: PqcAlgorithmGroup = {
  publicKeyAlgorithm: "RSA",
  keySize: 4096,
  curve: null,
  quantumStatus: "DISALLOWED_2035",
  deprecationYear: null,
  disallowedYear: 2035,
  certificates: 3,
};

describe("PQC dashboard model", () => {
  it("groups algorithms and keeps the earliest, highest-risk milestone", () => {
    const groups = buildAlgorithmGroups([
      rsa4096,
      {
        ...rsa4096,
        keySize: 2048,
        quantumStatus: "DEPRECATED_2030",
        deprecationYear: 2030,
        certificates: 2,
      },
      {
        publicKeyAlgorithm: "ML-KEM",
        keySize: null,
        curve: "ML-KEM-768",
        quantumStatus: "PQC_COMPLIANT",
        deprecationYear: null,
        disallowedYear: null,
        certificates: 1,
      },
      {
        publicKeyAlgorithm: "EC",
        keySize: 256,
        curve: "prime256v1",
        quantumStatus: "DISALLOWED_2035",
        deprecationYear: null,
        disallowedYear: 2035,
        certificates: 4,
      },
      {
        publicKeyAlgorithm: null,
        keySize: null,
        curve: null,
        quantumStatus: "UNKNOWN",
        deprecationYear: null,
        disallowedYear: null,
        certificates: 1,
      },
    ]);

    expect(groups).toEqual([
      expect.objectContaining({
        algorithm: "ML-KEM",
        count: 1,
        keyDetails: "ML-KEM-768",
        quantumStatus: "PQC_COMPLIANT",
      }),
      expect.objectContaining({
        algorithm: "RSA",
        count: 5,
        deprecationYear: 2030,
        disallowedYear: 2035,
        keyDetails: "4096-bit, 2048-bit",
        quantumStatus: "DISALLOWED_2035",
      }),
      expect.objectContaining({
        algorithm: "ECDSA",
        count: 4,
        keyDetails: "prime256v1",
      }),
      expect.objectContaining({
        algorithm: "Unknown algorithm",
        keyDetails: "Key metadata unavailable",
        quantumStatus: "UNKNOWN",
      }),
    ]);
  });

  it("builds percentage breakdowns for the algorithm status chart", () => {
    const summary = {
      totalCertificates: 10,
      pqcCompliant: 4,
      deprecated2030: 3,
      disallowed2035: 2,
      unknown: 1,
      highHndlRisk: 2,
    };

    expect(buildStatusBreakdown(summary)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: "Deprecated 2030", percentage: 30 }),
      ]),
    );
    expect(
      buildStatusBreakdown(undefined).every((item) => item.percentage === 0),
    ).toBe(true);
  });
});
