// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.api.model;

import io.swagger.v3.oas.annotations.media.Schema;

public record UpdateIntegrationRequest(
        @Schema(
                description = """
                        Replacement webhook URL for Slack or Teams.

                Required when updating a SLACK or TEAMS integration.
                Must be omitted for PAGERDUTY and SERVICENOW_ITSM.
                """,
                nullable = true)
        String webhookUrl,
        @Schema(
                description = """
                        Replacement PagerDuty Events API v2 routing key.

                Required when updating a PAGERDUTY integration.
                Must be omitted for SLACK, TEAMS, and SERVICENOW_ITSM.
                """,
                nullable = true)
        String routingKey,
        @Schema(
                description = """
                        Replacement ServiceNow base HTTPS URL.

                Required when updating a SERVICENOW_ITSM integration.
                Must be omitted for all other providers.
                """,
                nullable = true)
        String instanceUrl,
        @Schema(
                description = """
                        Replacement ServiceNow OAuth scope string.

                Optional when updating a SERVICENOW_ITSM integration.
                Must be omitted for all other providers.
                """,
                nullable = true)
        String oauthScope,
        @Schema(
                description = """
                        Replacement ServiceNow OAuth client id.

                Required when updating a SERVICENOW_ITSM integration.
                Must be omitted for all other providers.
                """,
                nullable = true)
        String clientId,
        @Schema(
                description = """
                        Replacement ServiceNow OAuth client secret.

                Required when updating a SERVICENOW_ITSM integration.
                Must be omitted for all other providers.
                """,
                nullable = true)
        String clientSecret
) {
}
