// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.api.model;

import com.certmanagement.support.integrations.domain.IntegrationProvider;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Schema(description = "Internal request for delivering a notification through an organization's active integration.")
public record SendIntegrationNotificationRequest(
        @Schema(description = "Target organization id.", example = "42")
        @NotNull @Positive Long orgId,
        @Schema(description = "Notification provider to use. Currently supported providers are TEAMS and SLACK.", example = "SLACK")
        @NotNull IntegrationProvider provider,
        @Schema(description = "Provider-agnostic notification content.")
        @NotNull @Valid IntegrationNotificationData data
) {
}
