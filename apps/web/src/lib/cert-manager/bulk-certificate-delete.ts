// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError } from "axios";

import { deleteCertificate } from "@/lib/backend/certs";
import { getApiErrorMessage } from "@/lib/backend/common";
import { canDeleteCertificateRecord } from "@/lib/cert-manager/certificates-page-helpers";
import { isIssuanceFailedCertificateStatus } from "@/lib/cert-manager/certificate-status";
import { TaskTimeoutError } from "@/lib/run-with-concurrency";
import type { SSLCertificateListItem } from "@/types/ssl";

/** Requests in flight at once: enough to be quick, few enough to spare the API. */
export const BULK_DELETE_CONCURRENCY = 5;
/** Matches the API client's own request timeout. */
export const BULK_DELETE_TIMEOUT_MS = 30_000;

/**
 * The managed domains (user-domain certificates) behind `rows`, once each. A
 * domain's certificate iterations share one id, and deleting it removes them all.
 */
export function collectDeletableDomainIds(
  rows: readonly SSLCertificateListItem[],
): string[] {
  const ids = new Set<string>();
  for (const row of rows) {
    if (canDeleteCertificateRecord(row) && row.userDomainCertId) {
      ids.add(String(row.userDomainCertId));
    }
  }
  return [...ids];
}

/** The rows "Select all failed" picks: failed issuances the user may delete. */
export function pickDeletableFailedCertificates(
  rows: SSLCertificateListItem[],
): SSLCertificateListItem[] {
  return rows.filter(
    (row) =>
      isIssuanceFailedCertificateStatus(row.status) &&
      canDeleteCertificateRecord(row),
  );
}

const pluralizeDomains = (count: number) =>
  `${count} domain${count === 1 ? "" : "s"}`;

/** Title and body of the confirmation; the body says exactly what is lost. */
export function getBulkDeleteConfirmation(count: number): {
  title: string;
  description: string;
} {
  const subject = count === 1 ? "the domain" : "each domain";
  return {
    title: `Delete ${pluralizeDomains(count)}?`,
    description: `This removes ${subject} with all its certificates and settings. Deployed certificates aren't rolled back. This can't be undone.`,
  };
}

/** A domain that is already gone is what the user asked for. */
function isAlreadyDeletedError(error: unknown): boolean {
  if (!(error instanceof AxiosError)) {
    return false;
  }
  const status = error.response?.status;
  return status === 404 || status === 410;
}

/** Deletes one managed domain; one that no longer exists counts as deleted. */
export async function deleteManagedDomain(
  userDomainCertId: string,
): Promise<void> {
  try {
    await deleteCertificate(userDomainCertId);
  } catch (error) {
    if (!isAlreadyDeletedError(error)) {
      throw error;
    }
  }
}

export interface BulkDeleteOutcome {
  deletedCount: number;
  failedIds: string[];
  skippedCount: number;
}

/** "Deleted 38. 2 couldn't be deleted." plus how many a stop left untouched. */
export function formatBulkDeleteSummary({
  deletedCount,
  failedIds,
  skippedCount,
}: BulkDeleteOutcome): string {
  const parts = [`Deleted ${deletedCount}.`];
  if (failedIds.length > 0) {
    parts.push(`${failedIds.length} couldn't be deleted.`);
  }
  if (skippedCount > 0) {
    parts.push(`Stopped before the other ${skippedCount}.`);
  }
  return parts.join(" ");
}

export const BULK_DELETE_TIMEOUT_MESSAGE =
  "The request timed out; it may still have completed. Retry to check.";
const UNKNOWN_FAILURE_MESSAGE = "Something went wrong.";

/** Statuses whose cause is clear enough to name in place of the API's words. */
const FAILURE_STATUS_HINTS: Readonly<Record<number, string>> = {
  403: "You don't have permission to delete these.",
  429: "Too many requests at once. Wait a moment, then retry.",
};

function getFailureStatus(error: unknown): number | undefined {
  return error instanceof AxiosError ? error.response?.status : undefined;
}

/** Failures in one class share one cause: a timeout, an HTTP status, or neither. */
function getFailureClass(error: unknown): string {
  if (error instanceof TaskTimeoutError) {
    return "timeout";
  }
  return `status:${getFailureStatus(error) ?? "none"}`;
}

function getFailureMessage(error: unknown): string {
  return error instanceof TaskTimeoutError
    ? BULK_DELETE_TIMEOUT_MESSAGE
    : getApiErrorMessage(error, UNKNOWN_FAILURE_MESSAGE);
}

/**
 * Why a run's deletes failed, for the summary toast. When every failure shares
 * one cause with a known hint (all 403s, say) that hint speaks for them all;
 * otherwise the first failure's own message stands in.
 *
 * @param errors Rejection reasons in the order the deletes settled.
 * @returns The reason to show, or null when nothing failed.
 */
export function describeBulkDeleteFailures(
  errors: readonly unknown[],
): string | null {
  if (errors.length === 0) {
    return null;
  }
  const [firstError] = errors;
  const firstClass = getFailureClass(firstError);
  const isSingleClass = errors.every(
    (error) => getFailureClass(error) === firstClass,
  );
  const statusHint = FAILURE_STATUS_HINTS[getFailureStatus(firstError) ?? -1];
  if (isSingleClass && statusHint) {
    return statusHint;
  }
  return getFailureMessage(firstError);
}

/** Progress copy while a run is going: the request being worked on, of all. */
export function formatBulkDeleteProgress(
  settledCount: number,
  total: number,
): string {
  return `Deleting ${Math.min(settledCount + 1, total)} of ${total}…`;
}
