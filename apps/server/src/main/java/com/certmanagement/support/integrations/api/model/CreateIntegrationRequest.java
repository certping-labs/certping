// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.api.model;

import com.certmanagement.support.integrations.domain.IntegrationProvider;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

public record CreateIntegrationRequest(
        @Schema(
                description = """
                        Integration provider to create.

                        Supported providers:
                        - SLACK: incoming webhook URL
                        - TEAMS: Teams workflow or incoming webhook URL
                        - PAGERDUTY: Events API v2 routing key
                        - SERVICENOW_ITSM: instanceUrl plus OAuth client credentials
                        """,
                example = "TEAMS")
        @NotNull IntegrationProvider provider,
        @Schema(
                description = """
                        Webhook URL for Slack or Teams.

                Required for SLACK and TEAMS.
                Must be omitted for PAGERDUTY and SERVICENOW_ITSM.
                """,
                example = "https://hooks.slack.com/services/your-workspace/your-channel/your-webhook-secret",
                nullable = true)
        String webhookUrl,
        @Schema(
                description = """
                        PagerDuty Events API v2 routing key.

                Required for PAGERDUTY.
                Must be omitted for SLACK, TEAMS, and SERVICENOW_ITSM.
                """,
                example = "0123456789abcdef0123456789abcdef",
                nullable = true)
        String routingKey,
        @Schema(
                description = """
                        Base HTTPS URL for a ServiceNow instance.

                Required for SERVICENOW_ITSM.
                Must be omitted for all other providers.
                Example: https://example.service-now.com
                """,
                example = "https://example.service-now.com",
                nullable = true)
        String instanceUrl,
        @Schema(
                description = """
                        Optional ServiceNow OAuth scope string.

                This value is sent to ServiceNow's token endpoint as the optional `scope` parameter.
                Use it only when the ServiceNow OAuth client is configured with specific scopes.
                Omit it when the instance uses the default authorized scope behavior.

                Optional for SERVICENOW_ITSM.
                Must be omitted for all other providers.
                """,
                example = "incident_write",
                nullable = true)
        String oauthScope,
        @Schema(
                description = """
                        ServiceNow OAuth client id.

                Required when provider is SERVICENOW_ITSM.
                Must be omitted for all other providers.
                """,
                example = "certping-support-client",
                nullable = true)
        String clientId,
        @Schema(
                description = """
                        ServiceNow OAuth client secret.

                Required when provider is SERVICENOW_ITSM.
                Must be omitted for all other providers.
                """,
                nullable = true)
        String clientSecret
) {
}
