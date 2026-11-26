// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  areCertificateTableFiltersEqual,
  buildCertificateDashboardQueryString,
  computeCertificateDashboardMetrics,
  filterCertificatesForCardView,
  readCertificateTableFilters,
  getCertificateIssuerOptions,
  getCertificateProviderOptions,
  sortCertificatesByAttention,
} from "@/lib/cert-manager/certificate-dashboard-helpers";
import type { SSLCertificateListItem } from "@/types/ssl";

function makeCertificate(
  overrides: Partial<SSLCertificateListItem>,
): SSLCertificateListItem {
  return {
    domain: "example.com",
    status: "ACTIVE",
    ...overrides,
  } as SSLCertificateListItem;
}

describe("certificate-dashboard-helpers", () => {
  describe("computeCertificateDashboardMetrics", () => {
    it("counts active, pending, expiring and failed certificates deterministically", () => {
      const now = new Date("2026-01-01T00:00:00.000Z");

      const metrics = computeCertificateDashboardMetrics(
        [
          makeCertificate({
            status: "ACTIVE",
            validTo: "2026-01-20T00:00:00.000Z",
          }),
          makeCertificate({
            status: "ACTIVE",
            validTo: "2026-03-15T00:00:00.000Z",
          }),
          makeCertificate({ status: "PENDING" }),
          makeCertificate({ status: "VALIDATING" }),
          makeCertificate({ status: "FAILED" }),
        ],
        now,
      );

      expect(metrics).toEqual({
        total: 5,
        active: 2,
        expiring: 1,
        pending: 2,
        failed: 1,
      });
    });

    it("groups every backend status into serving, pending and failed counts", () => {
      const now = new Date("2026-01-01T00:00:00.000Z");
      const metrics = computeCertificateDashboardMetrics(
        [
          makeCertificate({
            status: "RENEW_SUCCESS",
            validTo: "2026-01-10T00:00:00.000Z",
          }),
          makeCertificate({ status: "REVOKING" }),
          makeCertificate({ status: "REVOCATION_FAILED" }),
          makeCertificate({ status: "PENDING_DNS" }),
          makeCertificate({ status: "AWAITING_DNS" }),
          makeCertificate({ status: "RENEWING" }),
          makeCertificate({ status: "RENEWAL_FAILED" }),
          makeCertificate({ status: "CANCELLED_MANUAL" }),
          makeCertificate({ status: "EXPIRED" }),
        ],
        now,
      );

      // A failed renewal is not a failed issuance: ?status=FAILED would not show it.
      expect(metrics).toEqual({
        total: 9,
        active: 3,
        expiring: 1,
        pending: 3,
        failed: 0,
      });
    });

    it("ignores ACTIVE certificates missing validTo for expiring count", () => {
      const now = new Date("2026-01-01T00:00:00.000Z");
      const metrics = computeCertificateDashboardMetrics(
        [makeCertificate({ status: "ACTIVE", validTo: null })],
        now,
      );
      expect(metrics.expiring).toBe(0);
      expect(metrics.active).toBe(1);
    });

    it("does not count already-expired certificates as expiring soon", () => {
      const now = new Date("2026-01-15T00:00:00.000Z");
      const metrics = computeCertificateDashboardMetrics(
        [
          makeCertificate({
            status: "ACTIVE",
            validTo: "2026-01-01T00:00:00.000Z",
          }),
        ],
        now,
      );
      expect(metrics.expiring).toBe(0);
      expect(metrics.active).toBe(1);
    });
  });

  describe("getCertificateProviderOptions", () => {
    it("returns unique sorted providers, trimming whitespace", () => {
      expect(
        getCertificateProviderOptions([
          makeCertificate({ caProvider: " DIGICERT " }),
          makeCertificate({ caProvider: "LETS_ENCRYPT" }),
          makeCertificate({ caProvider: "DIGICERT" }),
          makeCertificate({ caProvider: " " }),
          makeCertificate({ caProvider: undefined }),
        ]),
      ).toEqual(["DIGICERT", "LETS_ENCRYPT"]);
    });
  });

  describe("filterCertificatesForCardView", () => {
    it("filters by search term, status, and provider", () => {
      const results = filterCertificatesForCardView({
        certificates: [
          makeCertificate({
            domain: "prod.example.com",
            certificateXref: "CERT-1",
            status: "ACTIVE",
            caProvider: "DIGICERT",
            managementState: "manual",
          }),
          makeCertificate({
            domain: "staging.example.com",
            certificateXref: "CERT-2",
            status: "PENDING",
            caProvider: "LETS_ENCRYPT",
            managementState: "fully-managed",
          }),
        ],
        searchTerm: "cert-1",
        statusFilter: "ACTIVE",
        providerFilter: "DIGICERT",
      });

      expect(results).toHaveLength(1);
      expect(results[0]?.domain).toBe("prod.example.com");
    });

    it("treats empty search term as match-all and supports 'all' filters", () => {
      const results = filterCertificatesForCardView({
        certificates: [makeCertificate({ domain: "prod.example.com" })],
        searchTerm: "   ",
        statusFilter: "all",
        providerFilter: "all",
      });
      expect(results).toHaveLength(1);
    });

    it("matches on management label text", () => {
      const results = filterCertificatesForCardView({
        certificates: [
          makeCertificate({
            domain: "prod.example.com",
            status: "ACTIVE",
            managementState: "fully-managed",
          }),
        ],
        searchTerm: "fully managed",
        statusFilter: "all",
        providerFilter: "all",
      });
      expect(results).toHaveLength(1);
    });
  });

  describe("buildCertificateDashboardQueryString", () => {
    it("replaces the filter keys from state and keeps everything else", () => {
      const currentSearchParams = new URLSearchParams(
        "search=old&status=FAILED&foo=bar&provider=OLD",
      );
      const nextQuery = buildCertificateDashboardQueryString({
        currentSearchParams,
        filterState: {
          status: "ACTIVE",
          caProvider: "DIGICERT",
          managementState: "manual",
          renewalWindow: "healthy",
        },
      });

      expect(nextQuery).toBe(
        "search=old&foo=bar&status=ACTIVE&provider=DIGICERT&managementState=manual&renewal=healthy",
      );
    });

    it("omits empty filters and preserves search", () => {
      const currentSearchParams = new URLSearchParams(
        "search=old&status=FAILED",
      );
      const nextQuery = buildCertificateDashboardQueryString({
        currentSearchParams,
        filterState: {},
      });
      expect(nextQuery).toBe("search=old");
    });

    it("is idempotent once the URL matches the filters", () => {
      const filterState = { status: "FAILED", caProvider: "DIGICERT" };
      const once = buildCertificateDashboardQueryString({
        currentSearchParams: new URLSearchParams("provider=X&search=a"),
        filterState,
      });
      expect(
        buildCertificateDashboardQueryString({
          currentSearchParams: new URLSearchParams(once),
          filterState,
        }),
      ).toBe(once);
    });
  });

  describe("readCertificateTableFilters", () => {
    it("maps URL params to table filter ids, dropping empty and all values", () => {
      expect(
        readCertificateTableFilters(
          new URLSearchParams(
            "status=FAILED&provider=%20DIGICERT%20&managementState=all&renewal=&search=x",
          ),
        ),
      ).toEqual({ status: "FAILED", caProvider: "DIGICERT" });
    });

    it("compares filters by value, not key order", () => {
      expect(
        areCertificateTableFiltersEqual(
          { status: "FAILED", caProvider: "X" },
          { caProvider: "X", status: "FAILED" },
        ),
      ).toBe(true);
      expect(areCertificateTableFiltersEqual({ status: "FAILED" }, {})).toBe(
        false,
      );
    });
  });
});

describe("certificate attention helpers", () => {
  const now = new Date("2026-10-01T00:00:00Z");
  const cert = (
    domain: string,
    status: SSLCertificateListItem["status"],
    extra: Partial<SSLCertificateListItem> = {},
  ): SSLCertificateListItem => ({ domain, status, ...extra });

  it("puts failed, then awaiting DNS, then expired and expiring certificates first", () => {
    const sorted = sortCertificatesByAttention(
      [
        cert("healthy.com", "ACTIVE", { validTo: "2027-06-01T00:00:00Z" }),
        cert("awaiting.com", "AWAITING_DNS"),
        cert("later.com", "ACTIVE", { validTo: "2026-10-20T00:00:00Z" }),
        cert("pending.com", "PENDING"),
        cert("soon.com", "ACTIVE", { validTo: "2026-10-05T00:00:00Z" }),
        cert("failed.com", "FAILED"),
        cert("expired.com", "EXPIRED"),
        cert("no-date.com", "ACTIVE"),
      ],
      now,
    );
    expect(sorted.map((item) => item.domain)).toEqual([
      "failed.com",
      "awaiting.com",
      "expired.com",
      "soon.com",
      "later.com",
      "healthy.com",
      "pending.com",
      "no-date.com",
    ]);
  });
});

describe("issuer filter", () => {
  const certificates = [
    { domain: "a.example", status: "ACTIVE", issuer: "R11" },
    { domain: "b.example", status: "ACTIVE", issuer: " E6 " },
    { domain: "c.example", status: "ACTIVE", issuer: "R11" },
    { domain: "d.example", status: "ACTIVE" },
  ] as unknown as SSLCertificateListItem[];

  it("lists distinct trimmed issuers in order", () => {
    expect(getCertificateIssuerOptions(certificates)).toEqual(["E6", "R11"]);
  });

  it("filters the card view by issuer and searches issuer names", () => {
    const byIssuer = filterCertificatesForCardView({
      certificates,
      searchTerm: "",
      statusFilter: "all",
      providerFilter: "all",
      issuerFilter: "R11",
    });
    expect(byIssuer.map((c) => c.domain)).toEqual(["a.example", "c.example"]);

    const bySearch = filterCertificatesForCardView({
      certificates,
      searchTerm: "e6",
      statusFilter: "all",
      providerFilter: "all",
    });
    expect(bySearch.map((c) => c.domain)).toEqual(["b.example"]);
  });

  it("reads and writes the issuer URL parameter", () => {
    expect(
      readCertificateTableFilters(new URLSearchParams("issuer=R11")),
    ).toEqual({ issuer: "R11" });
    expect(
      buildCertificateDashboardQueryString({
        currentSearchParams: new URLSearchParams("q=a"),
        filterState: { issuer: "R11" },
      }),
    ).toBe("q=a&issuer=R11");
  });
});
