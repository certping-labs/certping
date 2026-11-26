// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.integrations.api.model.CreateIntegrationRequest;
import com.certmanagement.support.integrations.api.model.UpdateIntegrationRequest;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class IntegrationPayloadValidatorTest {

    private final IntegrationPayloadValidator validator = new IntegrationPayloadValidator();

    private CreateIntegrationRequest create(IntegrationProvider p, String webhook, String routingKey,
                                            String instanceUrl, String scope, String clientId, String secret) {
        return new CreateIntegrationRequest(p, webhook, routingKey, instanceUrl, scope, clientId, secret);
    }

    // ===== SLACK =====

    @Test
    void slack_validWebhook_returnsConfig() {
        var payload = validator.validateForCreate(create(IntegrationProvider.SLACK,
                "https://hooks.slack.com/services/T1/B1/abcDEF123456", null, null, null, null, null));
        assertThat(payload.config()).containsEntry("webhook_host", "hooks.slack.com");
        assertThat(payload.secrets()).containsKey("webhook_url");
    }

    @Test
    void slack_govHost_isAccepted() {
        var payload = validator.validateForCreate(create(IntegrationProvider.SLACK,
                "https://hooks.slack-gov.com/services/T1/B1/x", null, null, null, null, null));
        assertThat(payload.config()).containsEntry("webhook_host", "hooks.slack-gov.com");
    }

    @Test
    void slack_wrongHost_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SLACK,
                "https://evil.example.com/services/x", null, null, null, null, null)))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("Slack webhook URL is invalid");
    }

    @Test
    void slack_wrongPath_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SLACK,
                "https://hooks.slack.com/wrong/x", null, null, null, null, null)))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void slack_nonHttps_rejected() {
        ApiException ex = catchThrowableOfType(() -> validator.validateForCreate(create(IntegrationProvider.SLACK,
                "http://hooks.slack.com/services/x", null, null, null, null, null)), ApiException.class);
        assertThat(ex.status()).isEqualTo(400);
        assertThat(ex.getMessage()).contains("must use HTTPS");
    }

    @Test
    void slack_missingWebhook_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SLACK,
                null, null, null, null, null, null)))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("required");
    }

    @Test
    void slack_unexpectedRoutingKey_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SLACK,
                "https://hooks.slack.com/services/x", "key", null, null, null, null)))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("not supported");
    }

    @Test
    void slack_invalidUrlSyntax_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SLACK,
                "https://hooks.slack.com/services/ space", null, null, null, null, null)))
                .isInstanceOf(ApiException.class);
    }

    // ===== TEAMS =====

    @Test
    void teams_validWebhook_returnsConfig() {
        var payload = validator.validateForCreate(create(IntegrationProvider.TEAMS,
                "https://outlook.office.com/webhook/abc", null, null, null, null, null));
        assertThat(payload.config()).containsEntry("webhook_host", "outlook.office.com");
    }

    @Test
    void teams_unexpectedInstanceUrl_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.TEAMS,
                "https://outlook.office.com/webhook/abc", null, "https://x.io", null, null, null)))
                .isInstanceOf(ApiException.class);
    }

    // ===== PAGERDUTY =====

    @Test
    void pagerduty_validRoutingKey_returnsSecret() {
        String key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"; // 32 alphanumeric
        var payload = validator.validateForCreate(create(IntegrationProvider.PAGERDUTY,
                null, key, null, null, null, null));
        assertThat(payload.secrets()).containsEntry("routing_key", key);
        assertThat(payload.config()).isEmpty();
    }

    @Test
    void pagerduty_invalidRoutingKey_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.PAGERDUTY,
                null, "too-short", null, null, null, null)))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("routingKey");
    }

    @Test
    void pagerduty_unexpectedWebhook_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.PAGERDUTY,
                "https://hooks.slack.com/services/x", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", null, null, null, null)))
                .isInstanceOf(ApiException.class);
    }

    // ===== SERVICENOW_ITSM =====

    @Test
    void servicenow_valid_returnsConfigAndSecrets() {
        var payload = validator.validateForCreate(create(IntegrationProvider.SERVICENOW_ITSM,
                null, null, "https://acme.service-now.com", "incident_write", "cid", "csecret"));
        assertThat(payload.config()).containsEntry("instance_host", "acme.service-now.com");
        assertThat(payload.config()).containsEntry("oauth_scope", "incident_write");
        assertThat(payload.secrets()).containsEntry("client_id", "cid");
        assertThat(payload.secrets()).containsEntry("client_secret", "csecret");
    }

    @Test
    void servicenow_noScope_omitsScope() {
        var payload = validator.validateForCreate(create(IntegrationProvider.SERVICENOW_ITSM,
                null, null, "https://acme.service-now.com", null, "cid", "csecret"));
        assertThat(payload.config()).doesNotContainKey("oauth_scope");
    }

    @Test
    void servicenow_urlWithPath_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SERVICENOW_ITSM,
                null, null, "https://acme.service-now.com/api", null, "cid", "csecret")))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("must not include a path");
    }

    @Test
    void servicenow_urlWithQuery_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SERVICENOW_ITSM,
                null, null, "https://acme.service-now.com?x=1", null, "cid", "csecret")))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("clean ServiceNow base URL");
    }

    @Test
    void servicenow_missingClientId_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SERVICENOW_ITSM,
                null, null, "https://acme.service-now.com", null, null, "csecret")))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("clientId");
    }

    @Test
    void servicenow_missingClientSecret_rejected() {
        assertThatThrownBy(() -> validator.validateForCreate(create(IntegrationProvider.SERVICENOW_ITSM,
                null, null, "https://acme.service-now.com", null, "cid", null)))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("clientSecret");
    }

    // ===== Update path =====

    @Test
    void update_slack_valid() {
        UpdateIntegrationRequest req = new UpdateIntegrationRequest(
                "https://hooks.slack.com/services/T1/B1/x", null, null, null, null, null);
        var payload = validator.validateForUpdate(IntegrationProvider.SLACK, req);
        assertThat(payload.config()).containsEntry("webhook_host", "hooks.slack.com");
    }

    @Test
    void update_pagerduty_valid() {
        UpdateIntegrationRequest req = new UpdateIntegrationRequest(
                null, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", null, null, null, null);
        var payload = validator.validateForUpdate(IntegrationProvider.PAGERDUTY, req);
        assertThat(payload.secrets()).containsKey("routing_key");
    }

    @Test
    void teamsWebhookIsPinnedToMicrosoftHosts() {
        for (String url : new String[] {
                "https://contoso.webhook.office.com/webhookb2/abc",
                "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x",
                "https://default123.ab.environment.api.powerplatform.com/powerautomate/automations/direct/x",
                "https://outlook.office.com/webhook/abc"}) {
            var payload = validator.validateForCreate(create(IntegrationProvider.TEAMS, url, null, null, null, null, null));
            assertThat(payload.config()).as(url).containsKey("webhook_host");
        }
        for (String url : new String[] {
                "https://attacker.example/webhook", "https://169.254.169.254/latest/meta-data",
                "https://webhook.office.com.attacker.example/x", "https://logic.azure.com/x",
                "https://contoso.webhook.office.com:8443/x", "https://user@contoso.webhook.office.com/x"}) {
            assertThatThrownBy(() -> validator.validateForCreate(
                    create(IntegrationProvider.TEAMS, url, null, null, null, null, null)))
                    .as(url).isInstanceOf(ApiException.class);
        }
    }
}
