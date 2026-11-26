// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.integrations.api.model.IntegrationNotificationData;
import com.certmanagement.support.integrations.api.model.SendIntegrationNotificationRequest;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.certmanagement.support.integrations.domain.IntegrationRepository;
import com.certmanagement.support.integrations.notification.NotificationContent;
import com.certmanagement.support.integrations.notification.SlackWebhookPayloadFactory;
import com.certmanagement.support.integrations.notification.TeamsWebhookPayloadFactory;
import com.certmanagement.support.integrations.notification.WebhookDeliveryClient;
import com.certmanagement.support.integrations.secret.SecretStore;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IntegrationNotificationService {

    private final IntegrationRepository integrationRepository;
    private final SecretStore secretStore;
    private final SlackWebhookPayloadFactory slackWebhookPayloadFactory;
    private final TeamsWebhookPayloadFactory teamsWebhookPayloadFactory;
    private final WebhookDeliveryClient webhookDeliveryClient;
    private final ObjectMapper objectMapper;

    public IntegrationNotificationService(
            IntegrationRepository integrationRepository,
            SecretStore secretStore,
            SlackWebhookPayloadFactory slackWebhookPayloadFactory,
            TeamsWebhookPayloadFactory teamsWebhookPayloadFactory,
            WebhookDeliveryClient webhookDeliveryClient,
            ObjectMapper objectMapper) {
        this.integrationRepository = integrationRepository;
        this.secretStore = secretStore;
        this.slackWebhookPayloadFactory = slackWebhookPayloadFactory;
        this.teamsWebhookPayloadFactory = teamsWebhookPayloadFactory;
        this.webhookDeliveryClient = webhookDeliveryClient;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public void sendNotification(SendIntegrationNotificationRequest request) {
        IntegrationProvider provider = request.provider();
        if (!provider.isWebhookProvider()) {
            throw new ApiException(400, "INTEGRATION_PROVIDER_UNSUPPORTED", "Only Teams and Slack notifications are supported currently");
        }

        Integration integration = integrationRepository
                .findByOrganizationIdAndProviderAndDeletedAtIsNull(request.orgId(), provider)
                .orElseThrow(() -> new ApiException(404, "INTEGRATION_NOT_FOUND", "Active integration not found"));

        String webhookUrl = requiredWebhookUrl(integration);
        Object payload = toPayload(provider, request.data());

        // This path is intentionally delivery-only. The caller service owns business audit
        // decisions, so this service just resolves the integration and performs the webhook post.
        webhookDeliveryClient.deliver(provider, URI.create(webhookUrl), payload);
    }

    private String requiredWebhookUrl(Integration integration) {
        String secretName = integration.getSecretRef("webhook_url");
        if (!StringUtils.hasText(secretName)) {
            throw new ApiException(500, "INTEGRATION_SECRET_REFERENCE_INVALID", "Integration secret reference is invalid");
        }

        String webhookUrl = secretStore.readSecret(secretName);
        if (!StringUtils.hasText(webhookUrl)) {
            throw new ApiException(500, "INTEGRATION_SECRET_REFERENCE_INVALID", "Integration secret reference is invalid");
        }
        return webhookUrl;
    }

    private Object toPayload(IntegrationProvider provider, IntegrationNotificationData data) {
        if (data.rawPayload() != null && !data.rawPayload().isNull()) {
            return validateRawPayload(provider, data.rawPayload());
        }

        NotificationContent content = toContent(data);
        return switch (provider) {
            case SLACK -> slackWebhookPayloadFactory.createPayload(content);
            case TEAMS -> teamsWebhookPayloadFactory.createPayload(content);
            default -> throw new ApiException(400, "INTEGRATION_PROVIDER_UNSUPPORTED", "Only Teams and Slack notifications are supported currently");
        };
    }

    private NotificationContent toContent(IntegrationNotificationData data) {
        if (!StringUtils.hasText(data.message())) {
            throw new ApiException(400, "INTEGRATION_NOTIFICATION_INVALID", "message is required when rawPayload is not provided");
        }
        Map<String, String> facts = new LinkedHashMap<>();
        if (data.facts() != null) {
            data.facts().forEach((key, value) -> {
                if (StringUtils.hasText(key) && StringUtils.hasText(value)) {
                    facts.put(key.trim(), value.trim());
                }
            });
        }
        // The internal API accepts provider-agnostic fields so callers do not need to know
        // Slack block JSON or Teams card JSON. Provider-specific formatting stays in one place.
        return new NotificationContent(
                trimToNull(data.title()),
                data.message().trim(),
                trimToNull(data.linkUrl()),
                trimToNull(data.linkText()),
                facts);
    }

    private Map<String, Object> validateRawPayload(IntegrationProvider provider, JsonNode rawPayload) {
        if (!rawPayload.isObject()) {
            throw new ApiException(400, "INTEGRATION_NOTIFICATION_INVALID", "rawPayload must be a JSON object");
        }

        Map<String, Object> payload = objectMapper.convertValue(rawPayload, new TypeReference<>() {});
        switch (provider) {
            case SLACK -> validateSlackRawPayload(rawPayload);
            case TEAMS -> validateTeamsRawPayload(rawPayload);
            default -> throw new ApiException(400, "INTEGRATION_PROVIDER_UNSUPPORTED", "Only Teams and Slack notifications are supported currently");
        }
        return payload;
    }

    private void validateSlackRawPayload(JsonNode rawPayload) {
        boolean hasText = hasNonBlankText(rawPayload.get("text"));
        boolean hasBlocks = rawPayload.has("blocks") && rawPayload.get("blocks").isArray() && rawPayload.get("blocks").size() > 0;
        if (!hasText && !hasBlocks) {
            throw new ApiException(400, "INTEGRATION_NOTIFICATION_INVALID", "Slack rawPayload must contain text or blocks");
        }
    }

    private void validateTeamsRawPayload(JsonNode rawPayload) {
        boolean hasText = hasNonBlankText(rawPayload.get("text"));
        boolean hasMessageEnvelope = hasNonBlankText(rawPayload.get("type")) && rawPayload.has("attachments");
        if (!hasText && !hasMessageEnvelope) {
            throw new ApiException(400, "INTEGRATION_NOTIFICATION_INVALID", "Teams rawPayload must contain text or a message attachment payload");
        }
    }

    private boolean hasNonBlankText(JsonNode node) {
        return node != null && node.isString() && StringUtils.hasText(node.asString());
    }

    private String trimToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}
