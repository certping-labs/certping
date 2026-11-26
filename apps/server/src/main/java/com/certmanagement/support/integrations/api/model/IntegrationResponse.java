// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.api.model;

import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.certmanagement.support.integrations.domain.IntegrationStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

public record IntegrationResponse(
        @Schema(description = "Internal integration identifier.", example = "42")
        Long id,
        @Schema(description = "Provider associated with this integration.", example = "SLACK")
        IntegrationProvider provider,
        @Schema(description = "Current lifecycle status for the integration record.", example = "ACTIVE")
        IntegrationStatus status,
        @Schema(description = "Timestamp when the integration record was created.", example = "2026-04-22T06:55:10Z")
        Instant createdAt,
        @Schema(description = "Timestamp when the integration record was last updated.", example = "2026-04-22T06:55:12Z")
        Instant updatedAt,
        @Schema(description = "Soft-delete timestamp. Null means the integration is still active.", example = "2026-04-23T08:10:00Z", nullable = true)
        Instant deletedAt
) {
}
