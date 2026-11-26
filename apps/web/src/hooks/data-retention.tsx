// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import {
  getGlobalRetentionSettings,
  getOrgRetentionSettings,
  purgeOrgSoftDeleted,
  setGlobalRetentionSettings,
  setOrgRetentionSettings,
} from "@/lib/backend/organizations";
import {
  getAuditRetention,
  updateAuditRetention,
  type AuditRetentionUpdate,
} from "@/lib/backend/audit-retention";
import { formatRetentionPeriod } from "@/lib/audit-retention";
import { formatDateTime } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

// ─── Query keys ───────────────────────────────────────────────────────────────

const ORG_RETENTION_KEY = (orgId: string | number) => [
  "org-retention-settings",
  String(orgId),
];
const GLOBAL_RETENTION_KEY = ["global-retention-settings"];
export const AUDIT_RETENTION_KEY = ["audit-retention-settings"] as const;

// ─── Org retention settings ───────────────────────────────────────────────────

export const useOrgRetentionSettings = (orgId: string | number) =>
  useQuery({
    queryKey: ORG_RETENTION_KEY(orgId),
    queryFn: () => getOrgRetentionSettings(orgId),
  });

export const useSetOrgRetentionSettings = (orgId: string | number) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (days: number | null) => setOrgRetentionSettings(orgId, days),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ORG_RETENTION_KEY(orgId) });
      toast.success("Retention period updated.");
    },
    onError: () => {
      toast.error("Failed to update retention period.");
    },
  });
};

// ─── Purge soft-deleted ───────────────────────────────────────────────────────

export const usePurgeOrgSoftDeleted = (orgId: string | number) => {
  return useMutation({
    mutationFn: () => purgeOrgSoftDeleted(orgId),
    onSuccess: (data) => {
      toast.success(
        `Purge complete. ${data.totalHardDeleted} records permanently deleted.`,
      );
    },
    onError: () => {
      toast.error("Purge failed. Please try again.");
    },
  });
};

// ─── Global retention settings (super admin) ──────────────────────────────────

export const useGlobalRetentionSettings = () =>
  useQuery({
    queryKey: GLOBAL_RETENTION_KEY,
    queryFn: getGlobalRetentionSettings,
  });

export const useSetGlobalRetentionSettings = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (days: number) => setGlobalRetentionSettings(days),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: GLOBAL_RETENTION_KEY });
      toast.success("Global retention period updated.");
    },
    onError: () => {
      toast.error("Failed to update global retention period.");
    },
  });
};

// ─── Audit log retention (super admin) ────────────────────────────────────────

/** The platform-wide audit retention setting. Only super admins may read it. */
export const useAuditRetention = ({ enabled }: { enabled: boolean }) =>
  useQuery({
    queryKey: AUDIT_RETENTION_KEY,
    queryFn: getAuditRetention,
    enabled,
    // A 403 means the caller isn't a super admin: asking again won't help.
    retry: false,
  });

/**
 * Confirms (and optionally changes) the audit retention period. The PUT
 * answers with the new setting, which replaces the cached one. Errors are left
 * to the caller, which shows them next to the form.
 */
export const useSetAuditRetention = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (update: AuditRetentionUpdate) => updateAuditRetention(update),
    onSuccess: (retention) => {
      queryClient.setQueryData(AUDIT_RETENTION_KEY, retention);
      // When the period applies is the server's answer (its schedule and grace).
      const appliesFrom = retention.effectiveFrom
        ? ` Applies from ${formatDateTime(retention.effectiveFrom)}.`
        : "";
      toast.success(
        `Audit retention confirmed: ${formatRetentionPeriod(retention.months)}.${appliesFrom}`,
      );
    },
  });
};
