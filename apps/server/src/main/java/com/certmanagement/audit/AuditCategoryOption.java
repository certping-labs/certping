// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * A category the audit page filters by ({@code GET /api/v1/audit-logs/categories}).
 *
 * @param featureKey the feature every event of the category belongs to; {@code null} when the category
 *                   is core or spans several features
 * @param enabled    whether any of its events belongs to a core feature or one that is on for the
 *                   organization read. Customers are only offered enabled categories; super admins see
 *                   every category with this flag
 */
@Schema(description = "A category of audit events to filter by")
public record AuditCategoryOption(
        @Schema(example = "CREDENTIALS") String key,
        @Schema(example = "Credentials") String label,
        @Schema(example = "CREDENTIALS_MANAGEMENT", nullable = true) String featureKey,
        @Schema(example = "true") boolean enabled) {
}
