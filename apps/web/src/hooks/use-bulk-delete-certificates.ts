// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useCallback, useRef, useState } from "react";
import { type QueryClient, useQueryClient } from "@tanstack/react-query";
import { type ExternalToast, toast } from "sonner";

import {
  invalidateAlertQueries,
  invalidateAuditQueries,
  invalidateCertificateDataQueries,
  invalidateDeploymentQueries,
} from "@/hooks/query-invalidation";
import {
  BULK_DELETE_CONCURRENCY,
  BULK_DELETE_TIMEOUT_MS,
  type BulkDeleteOutcome,
  deleteManagedDomain,
  describeBulkDeleteFailures,
  formatBulkDeleteSummary,
} from "@/lib/cert-manager/bulk-certificate-delete";
import { runWithConcurrency } from "@/lib/run-with-concurrency";

/** Long enough to reach Retry after reading the summary. */
const FAILURE_TOAST_DURATION_MS = 10_000;
/** One toast for every summary and retry notice, so they replace, never stack. */
const BULK_DELETE_TOAST_ID = "bulk-certificate-delete";
const RETRY_WHILE_RUNNING_MESSAGE = "Retry when the current run finishes.";

export interface BulkDeleteProgress {
  settledCount: number;
  total: number;
}

// Once per run, never per domain: a 40-domain run refetches the list once.
function refreshAfterBulkDelete(queryClient: QueryClient): Promise<unknown> {
  return Promise.all([
    invalidateCertificateDataQueries(queryClient),
    invalidateDeploymentQueries(queryClient),
    invalidateAlertQueries(queryClient),
    invalidateAuditQueries(queryClient),
  ]);
}

interface FailureSummaryToast {
  summary: string;
  reason: string | null;
  isRunActive: () => boolean;
  retry: () => void;
}

/**
 * The summary of a run with failures, with why they failed and a Retry. Retry
 * pressed while another run is going keeps this toast open and says so in it.
 */
function showFailureSummaryToast({
  summary,
  reason,
  isRunActive,
  retry,
}: FailureSummaryToast): void {
  const options: ExternalToast = {
    id: BULK_DELETE_TOAST_ID,
    duration: FAILURE_TOAST_DURATION_MS,
    action: {
      label: "Retry",
      onClick: (event) => {
        if (!isRunActive()) {
          retry();
          return;
        }
        event.preventDefault();
        toast.info(RETRY_WHILE_RUNNING_MESSAGE, {
          ...options,
          description: summary,
        });
      },
    },
  };
  toast.error(summary, { ...options, description: reason });
}

/**
 * Deletes managed domains in bulk: at most {@link BULK_DELETE_CONCURRENCY} requests
 * in flight, past failures, then one refresh and one summary toast whose Retry
 * resends only the domains that failed and says why they failed. One run at a
 * time: a second call while one is going is ignored, and Retry pressed then says
 * so in the same toast. `stop` lets in-flight requests finish and starts no more.
 */
export function useBulkDeleteCertificates() {
  const queryClient = useQueryClient();
  const [progress, setProgress] = useState<BulkDeleteProgress | null>(null);
  const activeRun = useRef<AbortController | null>(null);

  const deleteDomains = useCallback(
    async function runBulkDelete(
      userDomainCertIds: readonly string[],
    ): Promise<BulkDeleteOutcome | null> {
      if (activeRun.current || userDomainCertIds.length === 0) {
        return null;
      }
      const controller = new AbortController();
      activeRun.current = controller;
      const total = userDomainCertIds.length;
      setProgress({ settledCount: 0, total });

      try {
        const result = await runWithConcurrency(
          userDomainCertIds,
          deleteManagedDomain,
          {
            concurrency: BULK_DELETE_CONCURRENCY,
            timeoutMs: BULK_DELETE_TIMEOUT_MS,
            signal: controller.signal,
            onSettled: (settledCount) => setProgress({ settledCount, total }),
          },
        );
        const outcome: BulkDeleteOutcome = {
          deletedCount: result.succeeded.length,
          failedIds: result.failed.map((failure) => failure.item),
          skippedCount: result.skipped.length,
        };
        void refreshAfterBulkDelete(queryClient);

        const summary = formatBulkDeleteSummary(outcome);
        if (outcome.failedIds.length === 0) {
          toast.success(summary, { id: BULK_DELETE_TOAST_ID });
          return outcome;
        }
        showFailureSummaryToast({
          summary,
          reason: describeBulkDeleteFailures(
            result.failed.map((failure) => failure.error),
          ),
          isRunActive: () => activeRun.current !== null,
          retry: () => void runBulkDelete(outcome.failedIds),
        });
        return outcome;
      } finally {
        activeRun.current = null;
        setProgress(null);
      }
    },
    [queryClient],
  );

  const stop = useCallback(() => activeRun.current?.abort(), []);

  return { deleteDomains, stop, progress, isRunning: progress !== null };
}
