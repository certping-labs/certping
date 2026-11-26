// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.notification;

import java.util.Map;
import java.util.List;
import java.util.LinkedHashMap;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class TeamsWebhookPayloadFactory {

    public Map<String, Object> createPayload(NotificationContent content) {
        Map<String, Object> attachment = new LinkedHashMap<>();
        attachment.put("contentType", "application/vnd.microsoft.card.adaptive");
        attachment.put("contentUrl", null);
        attachment.put("content", Map.of(
                "$schema", "http://adaptivecards.io/schemas/adaptive-card.json",
                "type", "AdaptiveCard",
                "version", "1.4",
                "body", adaptiveBody(content),
                "actions", adaptiveActions(content)));
        return Map.of("type", "message", "attachments", List.of(attachment));
    }

    private List<Map<String, Object>> adaptiveBody(NotificationContent content) {
        java.util.ArrayList<Map<String, Object>> body = new java.util.ArrayList<>();
        if (StringUtils.hasText(content.title())) {
            body.add(Map.of(
                    "type", "TextBlock",
                    "text", content.title(),
                    "weight", "Bolder",
                    "size", "Medium",
                    "wrap", true));
        }
        body.add(Map.of(
                "type", "TextBlock",
                "text", content.message(),
                "wrap", true));
        if (!content.facts().isEmpty()) {
            body.add(Map.of(
                    "type", "FactSet",
                    "facts", content.facts().entrySet().stream()
                            .map(entry -> Map.of("title", entry.getKey(), "value", entry.getValue()))
                            .toList()));
        }
        return body;
    }

    private List<Map<String, Object>> adaptiveActions(NotificationContent content) {
        if (!StringUtils.hasText(content.linkUrl())) {
            return List.of();
        }
        String linkText = StringUtils.hasText(content.linkText()) ? content.linkText() : "Open";
        return List.of(Map.of(
                "type", "Action.OpenUrl",
                "title", linkText,
                "url", content.linkUrl()));
    }
}
