// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import axios from "axios";
import { z } from "zod";

import { apiClient, apiRoutes } from "@/lib/api";

/** Error code cert-manager answers an out-of-range period with (400), with the bounds in the body. */
export const AUDIT_RETENTION_OUT_OF_RANGE = "AUDIT_RETENTION_OUT_OF_RANGE";

const monthSchema = z
  .string()
  .regex(/^\d{4}-\d{2}$/)
  .nullish()
  .catch(null)
  .transform((value) => value ?? null);

const instantSchema = z
  .string()
  .nullish()
  .transform((value) => value ?? null);

const auditRetentionSchema = z.object({
  months: z.number().int(),
  retentionDays: z.number(),
  minMonths: z.number().int(),
  maxMonths: z.number().int(),
  effectiveFrom: instantSchema,
  oldestRetainedMonth: monthSchema,
  oldestStoredMonth: monthSchema,
  automaticDeletionEnabled: z.boolean(),
  updatedAt: instantSchema,
  previousMonths: z
    .number()
    .int()
    .nullish()
    .transform((value) => value ?? null),
  confirmed: z.boolean(),
  confirmedAt: instantSchema,
  /**
   * When the first deletion run would start if the period were confirmed now:
   * the first run at or after now + grace, from the job's real schedule; null
   * while the kill switch holds the job. Absent from older backends.
   */
  deletionWouldStartAt: z.string().nullable().optional(),
  /** What holds deletion now, if anything. Absent from older backends. */
  deletionHeldBy: z
    .enum(["KILL_SWITCH"])
    .nullable()
    .optional()
    .catch(undefined),
});

/**
 * The platform-wide audit retention setting (`GET/PUT
 * /api/v1/admin/settings/audit-retention`, super admin only). Months are
 * `YYYY-MM`, instants ISO-8601 UTC.
 */
export type AuditRetention = z.infer<typeof auditRetentionSchema>;

export interface AuditRetentionUpdate {
  months: number;
  reason: string;
}

export const getAuditRetention = async (): Promise<AuditRetention> => {
  const response = await apiClient.get<unknown>(
    apiRoutes.query.admin.auditRetentionSettings,
  );
  return auditRetentionSchema.parse(response.data);
};

/** Confirms the period, changing it first when it differs. Never deletes anything by itself. */
export const updateAuditRetention = async (
  update: AuditRetentionUpdate,
): Promise<AuditRetention> => {
  const response = await apiClient.put<unknown>(
    apiRoutes.mutation.admin.auditRetentionSettings,
    update,
  );
  return auditRetentionSchema.parse(response.data);
};

const outOfRangeSchema = z.object({
  code: z.literal(AUDIT_RETENTION_OUT_OF_RANGE),
  minMonths: z.number().int(),
  maxMonths: z.number().int(),
});

/** The bounds a 400 `AUDIT_RETENTION_OUT_OF_RANGE` carries; null for any other error. */
export const getAuditRetentionBounds = (
  error: unknown,
): { minMonths: number; maxMonths: number } | null => {
  if (!axios.isAxiosError(error)) return null;
  const parsed = outOfRangeSchema.safeParse(error.response?.data);
  return parsed.success
    ? { minMonths: parsed.data.minMonths, maxMonths: parsed.data.maxMonths }
    : null;
};
