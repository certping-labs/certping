// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.integrations.api.model.CreateIntegrationRequest;
import com.certmanagement.support.integrations.api.model.UpdateIntegrationRequest;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
class IntegrationPayloadValidator {

    private static final Pattern PAGERDUTY_ROUTING_KEY_PATTERN = Pattern.compile("^[A-Za-z0-9]{32}$");

    ValidatedIntegrationPayload validateForCreate(CreateIntegrationRequest request) {
        return validate(
                request.provider(),
                request.webhookUrl(),
                request.routingKey(),
                request.instanceUrl(),
                request.oauthScope(),
                request.clientId(),
                request.clientSecret());
    }

    ValidatedIntegrationPayload validateForUpdate(IntegrationProvider provider, UpdateIntegrationRequest request) {
        return validate(
                provider,
                request.webhookUrl(),
                request.routingKey(),
                request.instanceUrl(),
                request.oauthScope(),
                request.clientId(),
                request.clientSecret());
    }

    private ValidatedIntegrationPayload validate(
            IntegrationProvider provider,
            String webhookUrl,
            String routingKey,
            String instanceUrl,
            String oauthScope,
            String clientId,
            String clientSecret) {
        return switch (provider) {
            case SLACK -> validateSlack(webhookUrl, routingKey, instanceUrl, oauthScope, clientId, clientSecret);
            case TEAMS -> validateTeams(webhookUrl, routingKey, instanceUrl, oauthScope, clientId, clientSecret);
            case PAGERDUTY -> validatePagerDuty(webhookUrl, routingKey, instanceUrl, oauthScope, clientId, clientSecret);
            case SERVICENOW_ITSM -> validateServiceNow(
                    webhookUrl,
                    routingKey,
                    instanceUrl,
                    oauthScope,
                    clientId,
                    clientSecret);
        };
    }

    private ValidatedIntegrationPayload validateSlack(
            String webhookUrl,
            String routingKey,
            String instanceUrl,
            String oauthScope,
            String clientId,
            String clientSecret) {
        rejectUnexpected("routingKey", routingKey);
        rejectUnexpected("instanceUrl", instanceUrl);
        rejectUnexpected("oauthScope", oauthScope);
        rejectUnexpected("clientId", clientId);
        rejectUnexpected("clientSecret", clientSecret);
        URI webhookUri = requireWebhookUrl(IntegrationProvider.SLACK, webhookUrl);
        return new ValidatedIntegrationPayload(
                Map.of("webhook_host", webhookUri.getHost()),
                Map.of("webhook_url", webhookUrl.trim()));
    }

    private ValidatedIntegrationPayload validateTeams(
            String webhookUrl,
            String routingKey,
            String instanceUrl,
            String oauthScope,
            String clientId,
            String clientSecret) {
        rejectUnexpected("routingKey", routingKey);
        rejectUnexpected("instanceUrl", instanceUrl);
        rejectUnexpected("oauthScope", oauthScope);
        rejectUnexpected("clientId", clientId);
        rejectUnexpected("clientSecret", clientSecret);
        URI webhookUri = requireWebhookUrl(IntegrationProvider.TEAMS, webhookUrl);
        return new ValidatedIntegrationPayload(
                Map.of("webhook_host", webhookUri.getHost()),
                Map.of("webhook_url", webhookUrl.trim()));
    }

    private ValidatedIntegrationPayload validatePagerDuty(
            String webhookUrl,
            String routingKey,
            String instanceUrl,
            String oauthScope,
            String clientId,
            String clientSecret) {
        rejectUnexpected("webhookUrl", webhookUrl);
        rejectUnexpected("instanceUrl", instanceUrl);
        rejectUnexpected("oauthScope", oauthScope);
        rejectUnexpected("clientId", clientId);
        rejectUnexpected("clientSecret", clientSecret);
        // For this service we model PagerDuty incident creation through Events API v2, which
        // uses a service or orchestration routing key rather than a broader REST API credential.
        requirePattern(
                "routingKey",
                routingKey,
                PAGERDUTY_ROUTING_KEY_PATTERN,
                "routingKey must be a valid PagerDuty Events API routing key");
        return new ValidatedIntegrationPayload(Map.of(), Map.of("routing_key", routingKey.trim()));
    }

    private ValidatedIntegrationPayload validateServiceNow(
            String webhookUrl,
            String routingKey,
            String instanceUrl,
            String oauthScope,
            String clientId,
            String clientSecret) {
        rejectUnexpected("webhookUrl", webhookUrl);
        rejectUnexpected("routingKey", routingKey);
        URI instanceUri = requireServiceNowInstanceUrl(instanceUrl);
        requireNonBlank("clientId", clientId);
        requireNonBlank("clientSecret", clientSecret);

        Map<String, Object> config = new LinkedHashMap<>();
        config.put("instance_url", instanceUri.toString());
        config.put("instance_host", instanceUri.getHost());
        if (StringUtils.hasText(oauthScope)) {
            config.put("oauth_scope", oauthScope.trim());
        }

        return new ValidatedIntegrationPayload(
                Map.copyOf(config),
                Map.of(
                        "client_id", clientId.trim(),
                        "client_secret", clientSecret.trim()));
    }

    private URI requireWebhookUrl(IntegrationProvider provider, String webhookUrl) {
        URI uri = requireHttpsUrl("webhookUrl", webhookUrl);
        if (provider == IntegrationProvider.SLACK) {
            boolean validHost = "hooks.slack.com".equalsIgnoreCase(uri.getHost())
                    || "hooks.slack-gov.com".equalsIgnoreCase(uri.getHost());
            boolean validPath = uri.getPath() != null && uri.getPath().startsWith("/services/");
            if (!validHost || !validPath) {
                throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", "Slack webhook URL is invalid");
            }
        }
        if (provider == IntegrationProvider.TEAMS && !isTeamsWebhookHost(uri.getHost())) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID",
                    "Teams webhook URL must be a Microsoft webhook or workflow URL");
        }
        // Workflow URLs spell out :443; any other port is not a Microsoft or Slack endpoint.
        if (StringUtils.hasText(uri.getUserInfo()) || (uri.getPort() != -1 && uri.getPort() != 443)) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", "webhookUrl is invalid");
        }
        return uri;
    }

    /**
     * Where Microsoft issues Teams webhook URLs: the legacy Office 365 connectors (outlook.office.com,
     * outlook.office365.com, *.webhook.office.com), Workflows (Logic Apps, *.logic.azure.com) and Power
     * Automate environments (*.environment.api.powerplatform.com), with their US Government clouds.
     */
    static boolean isTeamsWebhookHost(String host) {
        if (!StringUtils.hasText(host)) {
            return false;
        }
        String h = host.toLowerCase(java.util.Locale.ROOT);
        if (TEAMS_EXACT_HOSTS.contains(h)) {
            return true;
        }
        for (String suffix : TEAMS_HOST_SUFFIXES) {
            if (h.endsWith(suffix) && h.length() > suffix.length()) {
                return true;
            }
        }
        return false;
    }

    private static final java.util.Set<String> TEAMS_EXACT_HOSTS = java.util.Set.of(
            "outlook.office.com", "outlook.office365.com", "outlook.office365.us");

    private static final java.util.List<String> TEAMS_HOST_SUFFIXES = java.util.List.of(
            ".webhook.office.com",
            ".webhook.office365.us",
            ".logic.azure.com",
            ".logic.azure.us",
            ".environment.api.powerplatform.com",
            ".environment.api.powerplatform.us");

    private URI requireHttpsUrl(String field, String value) {
        requireNonBlank(field, value);
        try {
            URI uri = URI.create(value.trim());
            if (!"https".equalsIgnoreCase(uri.getScheme()) || !StringUtils.hasText(uri.getHost())) {
                throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", field + " must use HTTPS");
            }
            return uri;
        } catch (IllegalArgumentException exception) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", field + " is invalid");
        }
    }

    private URI requireServiceNowInstanceUrl(String value) {
        URI uri = requireHttpsUrl("instanceUrl", value);
        if (StringUtils.hasText(uri.getPath()) && !"/".equals(uri.getPath())) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", "instanceUrl must not include a path");
        }
        if (StringUtils.hasText(uri.getQuery()) || StringUtils.hasText(uri.getFragment()) || StringUtils.hasText(uri.getUserInfo())) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", "instanceUrl must be a clean ServiceNow base URL");
        }
        return URI.create(uri.getScheme() + "://" + uri.getAuthority());
    }

    private void rejectUnexpected(String field, String value) {
        if (StringUtils.hasText(value)) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", field + " is not supported for this provider");
        }
    }

    private void rejectUnexpected(String field, Object value) {
        if (value != null) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", field + " is not supported for this provider");
        }
    }

    private void requirePattern(String field, String value, Pattern pattern, String message) {
        if (!StringUtils.hasText(value) || !pattern.matcher(value.trim()).matches()) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", message);
        }
    }

    private void requireNonBlank(String field, String value) {
        if (!StringUtils.hasText(value)) {
            throw new ApiException(400, "INTEGRATION_CONFIGURATION_INVALID", field + " is required");
        }
    }
}
