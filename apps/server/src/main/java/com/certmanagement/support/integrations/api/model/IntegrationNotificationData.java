// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.api.model;

import tools.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Size;
import java.util.Map;

@Schema(description = "Notification content. Use normalized fields for the common case, or provide rawPayload to send provider-native Slack/Teams JSON.")
public record IntegrationNotificationData(
        @Schema(description = "Optional short heading shown ahead of the message when the provider supports it.", example = "Certificate Expiry Warning")
        @Size(max = 160) String title,
        @Schema(description = "Primary notification message used by the normalized payload path.", example = "Certificate api.example.com expires in 5 days.")
        @Size(max = 4000) String message,
        @Schema(description = "Optional URL rendered as a call-to-action link when the provider supports it.", example = "https://certping.example.com/certificates/123")
        @Size(max = 2048) String linkUrl,
        @Schema(description = "Optional link label paired with linkUrl.", example = "Open certificate")
        @Size(max = 120) String linkText,
        @Schema(description = "Optional key-value facts rendered below the main message.")
        Map<String, String> facts,
        @Schema(
                description = "Optional provider-native webhook body. When present, this service sends it as-is after lightweight provider checks. For Slack, use a payload with text and blocks. For Teams, use a message payload with adaptive card attachments.",
                example = """
                        {
                          "text": "Certificate expiry warning",
                          "blocks": [
                            {
                              "type": "section",
                              "text": {
                                "type": "mrkdwn",
                                "text": "*Certificate api.example.com* expires in 5 days."
                              }
                            }
                          ]
                        }
                        """)
        JsonNode rawPayload
) {
}
