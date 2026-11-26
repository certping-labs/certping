// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { AuditRetention } from "@/lib/backend/audit-retention";

/**
 * A confirmed, running audit retention setting, as the server's
 * `GET /api/v1/admin/settings/audit-retention` returns it.
 */
export const auditRetentionFixture = (
  overrides: Partial<AuditRetention> = {},
): AuditRetention => ({
  months: 12,
  retentionDays: 365,
  minMonths: 6,
  maxMonths: 36,
  effectiveFrom: "2026-01-02T04:30:00Z",
  oldestRetainedMonth: "2025-01",
  oldestStoredMonth: "2023-01",
  automaticDeletionEnabled: true,
  updatedAt: "2025-12-20T12:00:00Z",
  previousMonths: null,
  confirmed: true,
  confirmedAt: "2025-12-20T12:00:00Z",
  ...overrides,
});

/** The state right after deploy: the default period, never confirmed, so nothing is deleted. */
export const unconfirmedAuditRetentionFixture = (
  overrides: Partial<AuditRetention> = {},
): AuditRetention =>
  auditRetentionFixture({
    effectiveFrom: null,
    updatedAt: null,
    confirmed: false,
    confirmedAt: null,
    ...overrides,
  });
