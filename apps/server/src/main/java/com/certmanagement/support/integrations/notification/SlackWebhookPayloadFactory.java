// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.notification;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class SlackWebhookPayloadFactory {

    public Map<String, Object> createPayload(NotificationContent content) {
        List<Map<String, Object>> blocks = new ArrayList<>();
        if (StringUtils.hasText(content.title())) {
            blocks.add(Map.of(
                    "type", "header",
                    "text", Map.of(
                            "type", "plain_text",
                            "text", content.title(),
                            "emoji", true)));
        }
        blocks.add(Map.of(
                "type", "section",
                "text", Map.of(
                        "type", "mrkdwn",
                        "text", content.message())));
        if (!content.facts().isEmpty()) {
            blocks.add(Map.of(
                    "type", "section",
                    "fields", content.facts().entrySet().stream()
                            .map(entry -> Map.of(
                                    "type", "mrkdwn",
                                    "text", "*" + entry.getKey() + "*\n" + entry.getValue()))
                            .toList()));
        }
        if (StringUtils.hasText(content.linkUrl())) {
            String linkText = StringUtils.hasText(content.linkText()) ? content.linkText() : "Open";
            blocks.add(Map.of(
                    "type", "actions",
                    "elements", List.of(Map.of(
                            "type", "button",
                            "text", Map.of(
                                    "type", "plain_text",
                                    "text", linkText,
                                    "emoji", true),
                            "url", content.linkUrl()))));
        }

        return Map.of("text", fallbackText(content), "blocks", blocks);
    }

    private String fallbackText(NotificationContent content) {
        if (StringUtils.hasText(content.title())) {
            return content.title() + ": " + content.message();
        }
        return content.message();
    }
}
