// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    },
  };
});

import { AxiosError, AxiosHeaders } from "axios";

import { apiClient } from "@/lib/api";
import {
  convertCertificateToAutomated,
  deleteCertificate,
  getCertificateByXref,
  getCertificateDetail,
  getCertificateDetailsRecord,
  getCertificateHistory,
  getCertificateTxtRecords,
  listAllCertificates,
  issueCertificate,
  issueManualCertificate,
  listCertificatesPage,
  listExpiringCertificates,
  renewCertificate,
  revokeCertificate,
  validateCertificateDns,
} from "@/lib/backend/certs";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
  delete: jest.Mock;
};

describe("certs adapter", () => {
  const createAxiosError = (status?: number) =>
    new AxiosError(
      "Request failed",
      "ERR_BAD_REQUEST",
      undefined,
      undefined,
      status
        ? {
            status,
            statusText: "Error",
            headers: {},
            config: { headers: new AxiosHeaders() },
            data: {},
          }
        : undefined,
    );

  beforeEach(() => {
    mockedApiClient.get.mockReset();
    mockedApiClient.post.mockReset();
    mockedApiClient.delete.mockReset();
  });

  it("maps list responses into normalized certificate summaries", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [
          {
            certificateXref: "cert_abc123",
            domain: "example.com",
            caProvider: "DIGICERT",
            status: "ACTIVE",
            sanDomains: ["www.example.com"],
            dnsConfigXref: "cred_dns_123",
            deploymentCredentialXrefs: ["cred_deploy_1"],
            validTo: "2027-01-01T00:00:00Z",
          },
        ],
        page: 0,
        size: 20,
        totalItems: 1,
        totalPages: 1,
      },
    });

    const result = await listCertificatesPage();

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      "/api/v1/certs",
      expect.objectContaining({ timeout: 120_000 }),
    );

    expect(result.items[0]).toEqual(
      expect.objectContaining({
        certificateXref: "cert_abc123",
        domain: "example.com",
        caProvider: "DIGICERT",
        status: "ACTIVE",
        rawStatus: "ACTIVE",
        sanDomains: ["www.example.com"],
        dnsConfigXref: "cred_dns_123",
        deploymentCredentialXrefs: ["cred_deploy_1"],
      }),
    );
  });

  it("resolves the main DNS credential by the certificate's root domain", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [
          {
            certificateXref: "cert-root",
            domain: "*.example.com",
            status: "ACTIVE",
            dnsConfigXref: {
              "partner.io": "cred-partner",
              "example.com": "cred-root",
            },
          },
        ],
        page: 0,
        size: 20,
        totalItems: 1,
        totalPages: 1,
      },
    });

    const result = await listCertificatesPage();

    expect(result.items[0].dnsConfigXref).toBe("cred-root");
  });

  it("normalizes nullable legacy list fields before they reach the UI", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [
          {
            certificateXref: " cert-legacy ",
            domain: null,
            caProvider: null,
            status: null,
          },
        ],
        page: 0,
        size: 20,
        totalItems: 1,
        totalPages: 1,
      },
    });

    const result = await listCertificatesPage();

    expect(result.items[0]).toEqual(
      expect.objectContaining({
        certificateXref: "cert-legacy",
        domain: "cert-legacy",
        caProvider: undefined,
        status: "UNKNOWN",
        rawStatus: "UNKNOWN",
      }),
    );
  });

  it("loads the expiring-certs slice with the service defaults", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [
          {
            domain: " example.com ",
            certificateXref: " cert-exp-1 ",
            validTo: "2026-04-01T00:00Z",
            status: "active",
            caProvider: "LETS_ENCRYPT",
            dnsCredentialKvPath: "kv/dns",
            certSecretHandle: "secret",
            deploymentCredentialXrefs: ["cred-deploy"],
          },
        ],
        page: 0,
        size: 20,
        hasNext: false,
        withinDays: 7,
      },
    });

    const result = await listExpiringCertificates();

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      "/api/v1/certs/expiring",
      expect.objectContaining({
        params: { withinDays: 7, page: 0, size: 20 },
      }),
    );
    expect(result).toEqual({
      items: [
        {
          domain: "example.com",
          certificateXref: "cert-exp-1",
          validTo: "2026-04-01T00:00Z",
          status: "ACTIVE",
          caProvider: "LETS_ENCRYPT",
        },
      ],
      page: 0,
      size: 20,
      hasNext: false,
      withinDays: 7,
    });
    expect(result.items[0]).not.toHaveProperty("dnsCredentialKvPath");
    expect(result.items[0]).not.toHaveProperty("certSecretHandle");
    expect(result.items[0]).not.toHaveProperty("deploymentCredentialXrefs");
  });

  it("forwards a custom expiring window and clamps page size to 100", async () => {
    const abortController = new AbortController();
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [
          {
            domain: "",
            certificateXref: "cert-exp-2",
            validTo: null,
            status: null,
            caProvider: null,
          },
          null,
          {
            domain: "missing-xref.example",
            certificateXref: "  ",
            status: "ACTIVE",
          },
        ],
        page: 2,
        size: 100,
        hasNext: true,
        withinDays: 30,
      },
    });

    const result = await listExpiringCertificates({
      withinDays: 30,
      page: 2,
      size: 250,
      signal: abortController.signal,
    });

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      "/api/v1/certs/expiring",
      expect.objectContaining({
        params: { withinDays: 30, page: 2, size: 100 },
        signal: abortController.signal,
      }),
    );
    expect(result).toEqual({
      items: [
        {
          domain: "cert-exp-2",
          certificateXref: "cert-exp-2",
          validTo: null,
          status: "UNKNOWN",
          caProvider: undefined,
        },
      ],
      page: 2,
      size: 100,
      hasNext: true,
      withinDays: 30,
    });
  });

  it("falls back when the expiring response omits the slice envelope", async () => {
    mockedApiClient.get.mockResolvedValue({ data: null });

    await expect(
      listExpiringCertificates({ size: 0, withinDays: 14, page: 1 }),
    ).resolves.toEqual({
      items: [],
      page: 1,
      size: 20,
      hasNext: false,
      withinDays: 14,
    });

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      "/api/v1/certs/expiring",
      expect.objectContaining({
        params: { withinDays: 14, page: 1, size: 20 },
      }),
    );
  });

  it("ignores a non-numeric expiring page size", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: { items: "not-an-array", hasNext: "yes" },
    });

    await expect(
      listExpiringCertificates({ size: Number.NaN }),
    ).resolves.toEqual({
      items: [],
      page: 0,
      size: 20,
      hasNext: false,
      withinDays: 7,
    });
  });

  it("forwards cancellation to the long-running list request", async () => {
    const abortController = new AbortController();
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [],
        page: 0,
        size: 100,
        totalItems: 0,
        totalPages: 0,
      },
    });

    await listCertificatesPage({ signal: abortController.signal });

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      "/api/v1/certs",
      expect.objectContaining({
        signal: abortController.signal,
        timeout: 120_000,
      }),
    );
  });

  it("falls back to domain lookup when an older route still passes a domain id", async () => {
    const notFoundError = new AxiosError(
      "Not found",
      "ERR_BAD_REQUEST",
      undefined,
      undefined,
      {
        status: 404,
        statusText: "Not Found",
        headers: {},
        config: { headers: new AxiosHeaders() },
        data: {},
      },
    );

    mockedApiClient.get
      .mockRejectedValueOnce(notFoundError)
      .mockResolvedValueOnce({
        data: {
          items: [
            {
              certificateXref: "cert_abc123",
              domain: "example.com",
              status: "ACTIVE",
            },
          ],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        },
      })
      .mockResolvedValueOnce({
        data: {
          certificateXref: "cert_abc123",
          domain: "example.com",
          status: "ACTIVE",
        },
      });

    const result = await getCertificateDetail("example.com");

    expect(result.certificateXref).toBe("cert_abc123");
    expect(result.domain).toBe("example.com");
    expect(mockedApiClient.get).toHaveBeenNthCalledWith(
      2,
      "/api/v1/certs",
      expect.objectContaining({
        params: {
          page: 0,
          size: 100,
        },
        timeout: 120_000,
      }),
    );
  });

  it("returns the direct certificate detail response shape", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        certificateXref: "cert-178515808995158",
        userDomainCertId: 1,
        domain: "example.org",
        caProvider: "LETS_ENCRYPT",
        status: "ACTIVE",
        wildcard: true,
        san: true,
        sanDomains: ["*.example.org"],
        dnsConfigXref: {
          "example.org": "cred-1776871284105-184039003161422",
        },
        deploymentCredentialXrefs: ["cred-184110005281218"],
        dnsCredentialKvPath:
          "https://example-vault.vault.azure.net/secrets/example-domain-cf-token/77d49a54ff9c40728cd99e40fc0b839b",
        deploymentCredentialKvPaths: [
          "https://example-vault.vault.azure.net/secrets/CERTPING-AWS-ACM-DEPLOYMENT-CREDENTIAL/fa560c40264448ea955d7d6a6022508f",
        ],
        certKvPath:
          "https://example-vault.vault.azure.net/secrets/cert-178515808995158/233168e95c244c0db8933b70ba3fb26c",
        issuer:
          "CN=(STAGING) Riddling Rhubarb R12,O=(STAGING) Let's Encrypt,C=US",
        serialNumber: "2CD13EF449DAA09A1169C8B4B3CF6FE0129C",
        fingerprintSha256:
          "9A:B6:37:68:83:CD:AB:B5:06:35:87:D9:6B:69:54:FB:59:24:6A:28:84:AA:5B:D3:F5:4E:6F:A1:C4:5E:36:19",
        validFrom: "2026-04-23T14:05:52Z",
        validTo: "2026-07-22T14:05:51Z",
        signatureAlgorithm: "SHA256withRSA",
        publicKeyAlgorithm: "RSA",
        keySize: 2048,
        certType: "DV",
      },
    });

    const result = await getCertificateDetailsRecord("cert-178515808995158");

    expect(result.userDomainCertId).toBe(1);
    expect(result.dnsConfigXref).toEqual({
      "example.org": "cred-1776871284105-184039003161422",
    });
    expect(result.deploymentCredentialXrefs).toEqual(["cred-184110005281218"]);
  });

  it("returns direct certificate detail without fallback when first lookup succeeds", async () => {
    mockedApiClient.get.mockResolvedValueOnce({
      data: {
        certificateXref: "cert-direct-1",
        domain: "direct.example.com",
        status: "ACTIVE",
      },
    });

    const result = await getCertificateDetail("cert-direct-1");
    expect(result.certificateXref).toBe("cert-direct-1");
    expect(mockedApiClient.get).toHaveBeenCalledTimes(1);
  });

  it("gets an exact certificate status by xref without list fallback", async () => {
    mockedApiClient.get.mockResolvedValueOnce({
      data: {
        certificateXref: "cert-status-1",
        userDomainCertId: 101,
        domain: "status.example.com",
        status: "PENDING",
      },
    });

    const result = await getCertificateByXref("cert-status-1");

    expect(result.userDomainCertId).toBe("101");
    expect(mockedApiClient.get).toHaveBeenCalledWith(
      "/api/v1/certs/cert-status-1",
    );
  });

  it.each([
    [{ export: { available: true, reason: null, formats: ["PKCS12"] } }, true],
    [
      { export: { available: false, reason: "NO_MATERIAL", formats: [] } },
      false,
    ],
    [{ export: "malformed" }, false],
    [{}, false],
    [{ exportAvailable: true }, true],
    [
      {
        exportAvailable: false,
        export: { available: true, reason: null, formats: ["PKCS12"] },
      },
      false,
    ],
  ])(
    "derives a polled certificate's download availability from %j",
    async (availability, expected) => {
      mockedApiClient.get.mockResolvedValueOnce({
        data: {
          certificateXref: "cert-status-1",
          domain: "status.example.com",
          status: "ACTIVE",
          ...availability,
        },
      });

      const result = await getCertificateByXref("cert-status-1");

      expect(result.exportAvailable).toBe(expected);
      expect(result).not.toHaveProperty("export");
    },
  );

  it("rethrows non-404 detail errors and unmatched fallback lookups", async () => {
    mockedApiClient.get.mockRejectedValueOnce(createAxiosError(500));
    await expect(getCertificateDetail("cert-500")).rejects.toBeInstanceOf(
      AxiosError,
    );

    mockedApiClient.get
      .mockRejectedValueOnce(createAxiosError(404))
      .mockResolvedValueOnce({
        data: {
          items: [
            { certificateXref: "cert-other", domain: "other.example.com" },
          ],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        },
      });

    await expect(
      getCertificateDetail("missing.example.com"),
    ).rejects.toBeInstanceOf(AxiosError);
  });

  it("rethrows fallback detail non-404 errors after identifier remap", async () => {
    mockedApiClient.get
      .mockRejectedValueOnce(createAxiosError(404))
      .mockResolvedValueOnce({
        data: {
          items: [
            { certificateXref: "cert-remap-1", domain: "remap.example.com" },
          ],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        },
      })
      .mockRejectedValueOnce(createAxiosError(500));

    await expect(
      getCertificateDetail("remap.example.com"),
    ).rejects.toBeInstanceOf(AxiosError);
  });

  it("submits the automated issuance payload using the latest contract", async () => {
    mockedApiClient.post.mockResolvedValue({
      data: {
        certificateXref: "cert_abc123",
        domain: "example.com",
        status: "PENDING",
      },
    });

    await issueCertificate({
      domain: "example.com",
      wildcard: false,
      san: true,
      caProvider: "DIGICERT",
      dnsCredentialXref: "cred_dns_123",
      sanDomainEntries: [{ patterns: ["www.example.com"] }],
      deploymentTargets: ["cred_deploy_1"],
    });

    expect(mockedApiClient.post).toHaveBeenCalledWith("/api/v1/certs/issue", {
      domain: "example.com",
      wildcard: false,
      san: true,
      caProvider: "DIGICERT",
      dnsCredentialXref: "cred_dns_123",
      sanDomainEntries: [{ patterns: ["www.example.com"] }],
      deploymentTargets: ["cred_deploy_1"],
    });
  });

  it("submits the manual issuance payload using the latest contract", async () => {
    mockedApiClient.post.mockResolvedValue({
      data: {
        certificateXref: "cert_abc123",
        domain: "example.com",
        status: "PENDING",
      },
    });

    await issueManualCertificate({
      domain: "example.com",
      wildcard: true,
      san: true,
      sanDomainEntries: [{ patterns: ["*.example.com", "www.example.com"] }],
    });

    expect(mockedApiClient.post).toHaveBeenCalledWith(
      "/api/v1/certs/issue-manual",
      {
        domain: "example.com",
        wildcard: true,
        san: true,
        sanDomainEntries: [{ patterns: ["*.example.com", "www.example.com"] }],
      },
    );
  });

  it("paginates all certificates using the typed backend contract", async () => {
    mockedApiClient.get
      .mockResolvedValueOnce({
        data: {
          items: [
            { certificateXref: "cert-1", domain: "a.com", status: "ACTIVE" },
          ],
          page: 0,
          size: 1,
          totalItems: 2,
          totalPages: 2,
        },
      })
      .mockResolvedValueOnce({
        data: {
          items: [
            { certificateXref: "cert-2", domain: "b.com", status: "FAILED" },
          ],
          page: 1,
          size: 1,
          totalItems: 2,
          totalPages: 2,
        },
      });

    const all = await listAllCertificates();
    expect(all).toHaveLength(2);
  });

  it("handles details fallback when final detail remains unavailable", async () => {
    const notFoundError = new AxiosError(
      "Not found",
      "ERR_BAD_REQUEST",
      undefined,
      undefined,
      {
        status: 404,
        statusText: "Not Found",
        headers: {},
        config: { headers: new AxiosHeaders() },
        data: {},
      },
    );

    mockedApiClient.get
      .mockRejectedValueOnce(notFoundError)
      .mockResolvedValueOnce({
        data: {
          items: [
            {
              certificateXref: "cert_abc123",
              domain: "example.com",
              status: "PENDING",
              validFrom: null,
              validTo: null,
            },
          ],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        },
      })
      .mockRejectedValueOnce(notFoundError);

    const result = await getCertificateDetailsRecord("example.com");
    expect(result.certificateXref).toBe("cert_abc123");
    expect(result.domain).toBe("example.com");
  });

  it("rethrows non-404 detail record errors and unmatched/mismatched fallbacks", async () => {
    mockedApiClient.get.mockRejectedValueOnce(createAxiosError(500));
    await expect(
      getCertificateDetailsRecord("cert-500"),
    ).rejects.toBeInstanceOf(AxiosError);

    mockedApiClient.get
      .mockRejectedValueOnce(createAxiosError(404))
      .mockResolvedValueOnce({
        data: {
          items: [{ certificateXref: "cert-1", domain: "known.example.com" }],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        },
      });
    await expect(
      getCertificateDetailsRecord("missing.example.com"),
    ).rejects.toBeInstanceOf(AxiosError);

    mockedApiClient.get
      .mockRejectedValueOnce(createAxiosError(404))
      .mockResolvedValueOnce({
        data: {
          items: [{ certificateXref: "cert-2", domain: "known2.example.com" }],
          page: 0,
          size: 100,
          totalItems: 1,
          totalPages: 1,
        },
      })
      .mockRejectedValueOnce(createAxiosError(500));
    await expect(
      getCertificateDetailsRecord("known2.example.com"),
    ).rejects.toBeInstanceOf(AxiosError);
  });

  it("covers automated convert/renew/revoke/delete/txt/history/dns validation helpers", async () => {
    mockedApiClient.post
      .mockResolvedValueOnce({
        data: {
          certificateXref: "cert-1",
          domain: "example.com",
          activationMode: "IMMEDIATE",
          inFlightPolicy: "WAIT",
          currentStatus: "ACTIVE",
        },
      })
      .mockResolvedValueOnce({
        data: {
          certificateXref: "cert-1",
          domain: "example.com",
          status: "PENDING",
        },
      })
      .mockResolvedValueOnce({
        data: {
          certificateXref: "cert-1",
          domain: "example.com",
          status: "REVOKING",
        },
      })
      .mockResolvedValueOnce({ data: {} });
    mockedApiClient.delete.mockResolvedValueOnce({ data: {} });
    mockedApiClient.get
      .mockResolvedValueOnce({
        data: {
          txtRecords: [
            {
              recordName: "_acme.example.com",
              recordValue: "txt-value",
              domain: "example.com",
            },
            {
              recordName: "",
              recordValue: "ignored",
              domain: "example.com",
            },
          ],
        },
      })
      .mockResolvedValueOnce({
        data: {
          items: [
            {
              certificateXref: "cert-1",
              userDomainCertId: 1,
              domain: "example.com",
              status: "ACTIVE",
            },
          ],
          page: 0,
          size: 20,
          totalItems: 1,
          totalPages: 1,
        },
      });

    await expect(
      convertCertificateToAutomated("cert-1", {
        dnsMappings: [{ domain: "example.com", credentialXref: "cred-1" }],
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        certificateXref: "cert-1",
        activationMode: "IMMEDIATE",
      }),
    );
    await expect(renewCertificate("cert-1")).resolves.toEqual(
      expect.objectContaining({ status: "PENDING" }),
    );
    await expect(
      revokeCertificate("cert-1", { reason: "rotated" }),
    ).resolves.toEqual(expect.objectContaining({ status: "REVOKING" }));
    await expect(validateCertificateDns("cert-1")).resolves.toBeUndefined();
    await expect(deleteCertificate("101")).resolves.toBeUndefined();
    expect(mockedApiClient.delete).toHaveBeenCalledWith(
      "/api/v1/user-domain-certificates/101",
    );
    await expect(getCertificateTxtRecords("cert-1")).resolves.toEqual([
      {
        recordName: "_acme.example.com",
        recordValue: "txt-value",
        domain: "example.com",
      },
      {
        recordName: "",
        recordValue: "ignored",
        domain: "example.com",
      },
    ]);
    await expect(getCertificateHistory({ udcId: "1" })).resolves.toEqual(
      expect.objectContaining({
        items: [expect.objectContaining({ certificateXref: "cert-1" })],
      }),
    );
  });

  it("preserves object-shaped DNS config references in certificate history", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        items: [
          {
            certificateXref: "cert-398362415069329",
            userDomainCertId: 7,
            domain: "example.org",
            status: "RENEWING",
            dnsConfigXref: {
              "example.org": "cred-373692904499335",
            },
            deploymentCredentialXrefs: ["cred-374441529368229"],
          },
        ],
        page: 0,
        size: 20,
        totalItems: 1,
        totalPages: 1,
      },
    });

    await expect(getCertificateHistory({ udcId: "7" })).resolves.toEqual(
      expect.objectContaining({
        items: [
          expect.objectContaining({
            dnsConfigXref: {
              "example.org": "cred-373692904499335",
            },
            deploymentCredentialXrefs: ["cred-374441529368229"],
          }),
        ],
      }),
    );
  });
});
