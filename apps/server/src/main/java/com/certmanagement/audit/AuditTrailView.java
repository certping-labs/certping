// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

/**
 * Which of the trail's views a query reads; each has its own scope in SQL ({@link AuditEventQueryStore}).
 *
 * <ul>
 *   <li>{@link #ACTIVITY}: an organization's customer rows, without the sensitive reads unless asked for
 *       by {@code category=ACCESS} ({@code GET /api/v1/audit-logs}).</li>
 *   <li>{@link #ACCESS}: an organization's sensitive reads only ({@code GET /api/v1/audit-logs/access}).</li>
 *   <li>{@link #PLATFORM}: every row of either visibility, of one organization or all
 *       ({@code GET /api/v1/admin/audit-logs}); super admins only.</li>
 * </ul>
 */
public enum AuditTrailView {
    ACTIVITY,
    ACCESS,
    PLATFORM
}
