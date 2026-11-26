// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.notification;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class WebhookPayloadFactoriesTest {

    private NotificationContent full() {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("Domain", "api.example.com");
        return new NotificationContent("Title", "Body message", "https://link", "Open it", facts);
    }

    private NotificationContent minimal() {
        return new NotificationContent(null, "Body only", null, null, null);
    }

    // ----------------------------- Slack -----------------------------

    @Test
    @SuppressWarnings("unchecked")
    void slack_full_buildsHeaderSectionFactsActions() {
        Map<String, Object> payload = new SlackWebhookPayloadFactory().createPayload(full());

        assertThat(payload.get("text")).isEqualTo("Title: Body message");
        List<Map<String, Object>> blocks = (List<Map<String, Object>>) payload.get("blocks");
        assertThat(blocks).extracting(b -> b.get("type"))
                .containsExactly("header", "section", "section", "actions");
    }

    @Test
    @SuppressWarnings("unchecked")
    void slack_minimal_onlySection() {
        Map<String, Object> payload = new SlackWebhookPayloadFactory().createPayload(minimal());
        assertThat(payload.get("text")).isEqualTo("Body only");
        List<Map<String, Object>> blocks = (List<Map<String, Object>>) payload.get("blocks");
        assertThat(blocks).hasSize(1);
        assertThat(blocks.get(0).get("type")).isEqualTo("section");
    }

    @Test
    @SuppressWarnings("unchecked")
    void slack_linkWithoutText_usesDefaultOpen() {
        NotificationContent content = new NotificationContent(null, "msg", "https://x", null, null);
        Map<String, Object> payload = new SlackWebhookPayloadFactory().createPayload(content);
        List<Map<String, Object>> blocks = (List<Map<String, Object>>) payload.get("blocks");
        Map<String, Object> actions = blocks.get(blocks.size() - 1);
        List<Map<String, Object>> elements = (List<Map<String, Object>>) actions.get("elements");
        Map<String, Object> text = (Map<String, Object>) elements.get(0).get("text");
        assertThat(text.get("text")).isEqualTo("Open");
    }

    // ----------------------------- Teams -----------------------------

    @Test
    @SuppressWarnings("unchecked")
    void teams_full_buildsAdaptiveCardWithActions() {
        Map<String, Object> payload = new TeamsWebhookPayloadFactory().createPayload(full());
        assertThat(payload.get("type")).isEqualTo("message");
        List<Map<String, Object>> attachments = (List<Map<String, Object>>) payload.get("attachments");
        Map<String, Object> content = (Map<String, Object>) attachments.get(0).get("content");
        List<Map<String, Object>> body = (List<Map<String, Object>>) content.get("body");
        assertThat(body).extracting(b -> b.get("type"))
                .containsExactly("TextBlock", "TextBlock", "FactSet");
        List<Map<String, Object>> actions = (List<Map<String, Object>>) content.get("actions");
        assertThat(actions).hasSize(1);
        assertThat(actions.get(0).get("title")).isEqualTo("Open it");
    }

    @Test
    @SuppressWarnings("unchecked")
    void teams_minimal_noFactsNoActions() {
        Map<String, Object> payload = new TeamsWebhookPayloadFactory().createPayload(minimal());
        List<Map<String, Object>> attachments = (List<Map<String, Object>>) payload.get("attachments");
        Map<String, Object> content = (Map<String, Object>) attachments.get(0).get("content");
        List<Map<String, Object>> body = (List<Map<String, Object>>) content.get("body");
        assertThat(body).hasSize(1);
        List<Map<String, Object>> actions = (List<Map<String, Object>>) content.get("actions");
        assertThat(actions).isEmpty();
    }

    @Test
    void notificationContent_nullFactsBecomesEmptyMap() {
        NotificationContent content = new NotificationContent("t", "m", null, null, null);
        assertThat(content.facts()).isEmpty();
    }
}
