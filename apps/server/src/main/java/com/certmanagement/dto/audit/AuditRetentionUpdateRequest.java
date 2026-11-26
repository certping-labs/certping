// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * A super admin's new audit retention period. The range (6 to 36 months) is checked by the service, so an
 * out-of-range value answers 400 {@code AUDIT_RETENTION_OUT_OF_RANGE} with the bounds.
 *
 * @param months whole months to keep audit events
 * @param reason why, for the platform's own trail (never shown to customers); 1 to 500 characters
 */
public record AuditRetentionUpdateRequest(
        @NotNull(message = "months is required") Integer months,
        @NotBlank(message = "reason is required")
        @Size(max = 500, message = "reason must be at most 500 characters") String reason) {
}
