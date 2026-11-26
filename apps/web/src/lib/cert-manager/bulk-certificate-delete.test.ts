// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, AxiosHeaders } from "axios";

import { deleteCertificate } from "@/lib/backend/certs";
import {
  BULK_DELETE_TIMEOUT_MESSAGE,
  collectDeletableDomainIds,
  deleteManagedDomain,
  describeBulkDeleteFailures,
  formatBulkDeleteProgress,
  formatBulkDeleteSummary,
  getBulkDeleteConfirmation,
  pickDeletableFailedCertificates,
} from "@/lib/cert-manager/bulk-certificate-delete";
import { TaskTimeoutError } from "@/lib/run-with-concurrency";
import type { SSLCertificateListItem } from "@/types/ssl";

jest.mock("@/lib/backend/certs", () => ({
  deleteCertificate: jest.fn(),
}));

const deleteCertificateMock = jest.mocked(deleteCertificate);

const row = (
  status: string,
  userDomainCertId?: string,
  domain = "example.com",
): SSLCertificateListItem => ({ domain, status, userDomainCertId });

function httpError(status: number, data: object = {}) {
  return new AxiosError("request failed", "ERR", undefined, undefined, {
    status,
    statusText: "",
    headers: {},
    config: { headers: new AxiosHeaders() },
    data,
  });
}

describe("bulk certificate delete", () => {
  it("collects each deletable managed domain once", () => {
    expect(
      collectDeletableDomainIds([
        row("FAILED", "1"),
        row("EXPIRED", "1"),
        row("PENDING", "2"),
        row("ACTIVE", "3"),
        row("RENEWAL_FAILED", "4"),
        row("FAILED"),
      ]),
    ).toEqual(["1", "2"]);
  });

  it("picks only deletable failed issuances for 'Select all failed'", () => {
    const failed = row("FAILED", "1");
    expect(
      pickDeletableFailedCertificates([
        failed,
        row("FAILED"),
        row("RENEWAL_FAILED", "2"),
        row("EXPIRED", "3"),
      ]),
    ).toEqual([failed]);
  });

  it("words the confirmation for one domain and for many", () => {
    expect(getBulkDeleteConfirmation(3)).toEqual({
      title: "Delete 3 domains?",
      description:
        "This removes each domain with all its certificates and settings. Deployed certificates aren't rolled back. This can't be undone.",
    });
    expect(getBulkDeleteConfirmation(1)).toEqual({
      title: "Delete 1 domain?",
      description:
        "This removes the domain with all its certificates and settings. Deployed certificates aren't rolled back. This can't be undone.",
    });
  });

  it("summarises deletes, failures and a stopped run", () => {
    expect(
      formatBulkDeleteSummary({
        deletedCount: 38,
        failedIds: ["a", "b"],
        skippedCount: 0,
      }),
    ).toBe("Deleted 38. 2 couldn't be deleted.");
    expect(
      formatBulkDeleteSummary({
        deletedCount: 4,
        failedIds: [],
        skippedCount: 0,
      }),
    ).toBe("Deleted 4.");
    expect(
      formatBulkDeleteSummary({
        deletedCount: 5,
        failedIds: [],
        skippedCount: 7,
      }),
    ).toBe("Deleted 5. Stopped before the other 7.");
  });

  it("shows the request being worked on, never past the total", () => {
    expect(formatBulkDeleteProgress(0, 40)).toBe("Deleting 1 of 40…");
    expect(formatBulkDeleteProgress(11, 40)).toBe("Deleting 12 of 40…");
    expect(formatBulkDeleteProgress(40, 40)).toBe("Deleting 40 of 40…");
  });

  describe("describeBulkDeleteFailures", () => {
    const permissionHint = "You don't have permission to delete these.";

    it("gives no reason when nothing failed", () => {
      expect(describeBulkDeleteFailures([])).toBeNull();
    });

    it("names the shared cause when every failure is a 403", () => {
      expect(
        describeBulkDeleteFailures([
          httpError(403, { message: "Forbidden" }),
          httpError(403),
        ]),
      ).toBe(permissionHint);
    });

    it("hints at waiting when every failure was rate limited", () => {
      expect(describeBulkDeleteFailures([httpError(429)])).toBe(
        "Too many requests at once. Wait a moment, then retry.",
      );
    });

    it("falls back to the first failure's API message when causes differ", () => {
      expect(
        describeBulkDeleteFailures([
          httpError(409, { message: "Domain has active deployments" }),
          httpError(403),
        ]),
      ).toBe("Domain has active deployments");
      expect(describeBulkDeleteFailures([httpError(403), httpError(500)])).toBe(
        "request failed",
      );
    });

    it("uses the first failure's message when its class has no hint", () => {
      expect(
        describeBulkDeleteFailures([
          httpError(500, { message: "Upstream unavailable" }),
          httpError(500),
        ]),
      ).toBe("Upstream unavailable");
      expect(describeBulkDeleteFailures([new Error("Network Error")])).toBe(
        "Network Error",
      );
      expect(describeBulkDeleteFailures(["opaque"])).toBe(
        "Something went wrong.",
      );
    });

    it("explains a timeout may still have deleted the domain", () => {
      expect(BULK_DELETE_TIMEOUT_MESSAGE).toBe(
        "The request timed out; it may still have completed. Retry to check.",
      );
      expect(
        describeBulkDeleteFailures([
          new TaskTimeoutError(30_000),
          new TaskTimeoutError(30_000),
        ]),
      ).toBe(BULK_DELETE_TIMEOUT_MESSAGE);
      expect(
        describeBulkDeleteFailures([
          new TaskTimeoutError(30_000),
          httpError(403),
        ]),
      ).toBe(BULK_DELETE_TIMEOUT_MESSAGE);
    });
  });

  describe("deleteManagedDomain", () => {
    it("deletes through the managed-domain endpoint", async () => {
      deleteCertificateMock.mockResolvedValue(undefined);
      await deleteManagedDomain("42");
      expect(deleteCertificateMock).toHaveBeenCalledWith("42");
    });

    it.each([404, 410])("treats a %s as already gone", async (status) => {
      deleteCertificateMock.mockRejectedValue(httpError(status));
      await expect(deleteManagedDomain("42")).resolves.toBeUndefined();
    });

    it("rethrows any other failure", async () => {
      const failure = httpError(500);
      deleteCertificateMock.mockRejectedValue(failure);
      await expect(deleteManagedDomain("42")).rejects.toBe(failure);
      deleteCertificateMock.mockRejectedValue(new Error("offline"));
      await expect(deleteManagedDomain("42")).rejects.toThrow("offline");
    });
  });
});
