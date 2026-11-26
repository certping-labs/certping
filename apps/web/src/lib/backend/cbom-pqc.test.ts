// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      get: jest.fn(),
    },
  };
});

import { apiClient, apiRoutes } from "@/lib/api";
import {
  getCbomDocument,
  getPqcReadinessCertificates,
  getPqcReadinessReport,
} from "@/lib/backend/cbom-pqc";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
};

describe("cbom-pqc adapter", () => {
  beforeEach(() => {
    mockedApiClient.get.mockReset();
  });

  it("fetches and formats the CycloneDX CBOM document", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        components: [{ name: "example.com" }],
      },
    });

    const result = await getCbomDocument();

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.certs.cbom,
    );
    expect(result.text).toContain('"bomFormat": "CycloneDX"');
    expect(result.text).toContain('"specVersion": "1.6"');
  });

  it("parses CBOM string responses before rendering them", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: '{"bomFormat":"CycloneDX","specVersion":"1.6"}',
    });

    const result = await getCbomDocument();

    expect(result.text).toBe(
      '{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.6"\n}',
    );
  });

  it("maps the typed PQC readiness summary to the dashboard model", async () => {
    const algorithms = [
      {
        publicKeyAlgorithm: "RSA",
        keySize: 2048,
        curve: null,
        quantumStatus: "DEPRECATED_2030",
        deprecationYear: 2030,
        disallowedYear: 2035,
        certificates: 2,
      },
    ];
    mockedApiClient.get.mockResolvedValue({
      data: {
        summary: {
          total: 2,
          pqcCompliant: 1,
          deprecated2030: 0,
          disallowed2035: 1,
          unknown: 0,
          highHndlRisk: 1,
        },
        algorithms,
      },
    });

    const result = await getPqcReadinessReport();

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.certs.pqcReadiness,
    );
    expect(result.summary).toEqual({
      totalCertificates: 2,
      pqcCompliant: 1,
      deprecated2030: 0,
      disallowed2035: 1,
      unknown: 0,
      highHndlRisk: 1,
    });
    expect(result.algorithms).toBe(algorithms);
  });

  it("maps a page of PQC certificates and forwards the filter and page params", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        content: [
          {
            certificateXref: "cert-10",
            commonName: "api.example.com",
            signatureAlgorithm: "SHA256withRSA",
            publicKeyAlgorithm: "EC",
            keySize: 4096,
            curve: null,
            quantumStatus: "DISALLOWED_2035",
            hndlRisk: "HIGH",
            deprecationYear: null,
            disallowedYear: 2035,
            complianceRef: "NIST IR 8547",
            remediationAdvice: "Plan migration.",
          },
          {
            certificateXref: "cert-11",
            commonName: "legacy.example.com",
            signatureAlgorithm: null,
            publicKeyAlgorithm: null,
            keySize: null,
            curve: null,
            quantumStatus: "UNKNOWN",
            hndlRisk: "UNKNOWN",
            deprecationYear: null,
            disallowedYear: null,
            complianceRef: null,
            remediationAdvice: "Reissue to collect algorithm metadata.",
          },
        ],
        totalElements: 40,
        totalPages: 3,
        size: 15,
        number: 1,
      },
    });

    const result = await getPqcReadinessCertificates({
      quantumStatus: "DISALLOWED_2035",
      page: 1,
      size: 15,
    });

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.certs.pqcReadinessCertificates,
      { params: { quantumStatus: "DISALLOWED_2035", page: 1, size: 15 } },
    );
    expect(result.totalElements).toBe(40);
    expect(result.number).toBe(1);
    expect(result.content[0]).toEqual(
      expect.objectContaining({
        certificateId: null,
        certificateXref: "cert-10",
        commonName: "api.example.com",
        keyAlgorithm: "ECDSA",
        quantumStatus: "DISALLOWED_2035",
        hndlRisk: "HIGH",
      }),
    );
    expect(result.content[1]).toEqual(
      expect.objectContaining({
        certificateXref: "cert-11",
        keyAlgorithm: "",
        signatureAlgorithm: "",
        complianceRef: "",
      }),
    );
  });
});
