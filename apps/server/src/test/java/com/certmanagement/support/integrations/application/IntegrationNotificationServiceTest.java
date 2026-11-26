// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.integrations.api.model.IntegrationNotificationData;
import com.certmanagement.support.integrations.api.model.SendIntegrationNotificationRequest;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.certmanagement.support.integrations.domain.IntegrationRepository;
import com.certmanagement.support.integrations.notification.SlackWebhookPayloadFactory;
import com.certmanagement.support.integrations.notification.TeamsWebhookPayloadFactory;
import com.certmanagement.support.integrations.notification.WebhookDeliveryClient;
import com.certmanagement.support.integrations.secret.SecretStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IntegrationNotificationServiceTest {

    private static final ObjectMapper MAPPER = JsonMapper.builderWithJackson2Defaults().build();

    @Mock
    private IntegrationRepository integrationRepository;
    @Mock
    private SecretStore secretStore;
    @Mock
    private SlackWebhookPayloadFactory slackWebhookPayloadFactory;
    @Mock
    private TeamsWebhookPayloadFactory teamsWebhookPayloadFactory;
    @Mock
    private WebhookDeliveryClient webhookDeliveryClient;

    private IntegrationNotificationService service;

    @BeforeEach
    void setUp() {
        service = new IntegrationNotificationService(
                integrationRepository, secretStore, slackWebhookPayloadFactory,
                teamsWebhookPayloadFactory, webhookDeliveryClient, MAPPER);
    }

    private Integration slackIntegration() {
        return new Integration(5L, IntegrationProvider.SLACK, Map.of(),
                Map.of("webhook_url", "secret-name"), 9L);
    }

    private SendIntegrationNotificationRequest request(IntegrationProvider provider, IntegrationNotificationData data) {
        return new SendIntegrationNotificationRequest(5L, provider, data);
    }

    private IntegrationNotificationData normalized() {
        return new IntegrationNotificationData("Title", "Message", "https://link", "Open",
                Map.of("Domain", "x.com"), null);
    }

    private JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void sendNotification_slackNormalized_delivers() {
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(Optional.of(slackIntegration()));
        when(secretStore.readSecret("secret-name")).thenReturn("https://hooks.slack.com/x");
        when(slackWebhookPayloadFactory.createPayload(any())).thenReturn(Map.of("text", "hi"));

        service.sendNotification(request(IntegrationProvider.SLACK, normalized()));

        verify(webhookDeliveryClient).deliver(eq(IntegrationProvider.SLACK), any(), any());
    }

    @Test
    void sendNotification_teamsNormalized_delivers() {
        Integration teams = new Integration(5L, IntegrationProvider.TEAMS, Map.of(),
                Map.of("webhook_url", "sn"), 9L);
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.TEAMS))
                .thenReturn(Optional.of(teams));
        when(secretStore.readSecret("sn")).thenReturn("https://teams.example.com/x");
        when(teamsWebhookPayloadFactory.createPayload(any())).thenReturn(Map.of("type", "message"));

        service.sendNotification(request(IntegrationProvider.TEAMS, normalized()));
        verify(webhookDeliveryClient).deliver(eq(IntegrationProvider.TEAMS), any(), any());
    }

    @Test
    void sendNotification_unsupportedProvider_throws400() {
        ApiException ex = catchThrowableOfType(
                () -> service.sendNotification(request(IntegrationProvider.PAGERDUTY, normalized())),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(400);
        assertThat(ex.code()).isEqualTo("INTEGRATION_PROVIDER_UNSUPPORTED");
    }

    @Test
    void sendNotification_integrationNotFound_throws404() {
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(Optional.empty());

        ApiException ex = catchThrowableOfType(
                () -> service.sendNotification(request(IntegrationProvider.SLACK, normalized())),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(404);
    }

    @Test
    void sendNotification_missingSecretRef_throws500() {
        Integration noRef = new Integration(5L, IntegrationProvider.SLACK, Map.of(), Map.of(), 9L);
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(Optional.of(noRef));

        ApiException ex = catchThrowableOfType(
                () -> service.sendNotification(request(IntegrationProvider.SLACK, normalized())),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(500);
        assertThat(ex.code()).isEqualTo("INTEGRATION_SECRET_REFERENCE_INVALID");
    }

    @Test
    void sendNotification_blankSecretValue_throws500() {
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(Optional.of(slackIntegration()));
        when(secretStore.readSecret("secret-name")).thenReturn("  ");

        ApiException ex = catchThrowableOfType(
                () -> service.sendNotification(request(IntegrationProvider.SLACK, normalized())),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(500);
    }

    @Test
    void sendNotification_missingMessage_throws400() {
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(Optional.of(slackIntegration()));
        when(secretStore.readSecret("secret-name")).thenReturn("https://hooks.slack.com/x");

        IntegrationNotificationData noMessage = new IntegrationNotificationData(
                "Title", "  ", null, null, null, null);
        ApiException ex = catchThrowableOfType(
                () -> service.sendNotification(request(IntegrationProvider.SLACK, noMessage)),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(400);
        assertThat(ex.code()).isEqualTo("INTEGRATION_NOTIFICATION_INVALID");
    }

    @Test
    void sendNotification_slackRawPayloadValid_delivers() {
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(Optional.of(slackIntegration()));
        when(secretStore.readSecret("secret-name")).thenReturn("https://hooks.slack.com/x");

        IntegrationNotificationData raw = new IntegrationNotificationData(
                null, null, null, null, null, json("{\"text\":\"hello\"}"));
        service.sendNotification(request(IntegrationProvider.SLACK, raw));
        verify(webhookDeliveryClient).deliver(eq(IntegrationProvider.SLACK), any(), any());
    }

    @Test
    void sendNotification_slackRawPayloadMissingTextAndBlocks_throws400() {
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(Optional.of(slackIntegration()));
        when(secretStore.readSecret("secret-name")).thenReturn("https://hooks.slack.com/x");

        IntegrationNotificationData raw = new IntegrationNotificationData(
                null, null, null, null, null, json("{\"foo\":\"bar\"}"));
        ApiException ex = catchThrowableOfType(
                () -> service.sendNotification(request(IntegrationProvider.SLACK, raw)),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(400);
        assertThat(ex.code()).isEqualTo("INTEGRATION_NOTIFICATION_INVALID");
    }

    @Test
    void sendNotification_rawPayloadNotObject_throws400() {
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(Optional.of(slackIntegration()));
        when(secretStore.readSecret("secret-name")).thenReturn("https://hooks.slack.com/x");

        IntegrationNotificationData raw = new IntegrationNotificationData(
                null, null, null, null, null, json("[1,2,3]"));
        ApiException ex = catchThrowableOfType(
                () -> service.sendNotification(request(IntegrationProvider.SLACK, raw)),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(400);
        assertThat(ex.code()).isEqualTo("INTEGRATION_NOTIFICATION_INVALID");
    }

    @Test
    void sendNotification_teamsRawPayloadWithEnvelope_delivers() {
        Integration teams = new Integration(5L, IntegrationProvider.TEAMS, Map.of(),
                Map.of("webhook_url", "sn"), 9L);
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.TEAMS))
                .thenReturn(Optional.of(teams));
        when(secretStore.readSecret("sn")).thenReturn("https://teams.example.com/x");

        IntegrationNotificationData raw = new IntegrationNotificationData(
                null, null, null, null, null,
                json("{\"type\":\"message\",\"attachments\":[]}"));
        service.sendNotification(request(IntegrationProvider.TEAMS, raw));
        verify(webhookDeliveryClient).deliver(eq(IntegrationProvider.TEAMS), any(), any());
    }

    @Test
    void sendNotification_teamsRawPayloadInvalid_throws400() {
        Integration teams = new Integration(5L, IntegrationProvider.TEAMS, Map.of(),
                Map.of("webhook_url", "sn"), 9L);
        when(integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.TEAMS))
                .thenReturn(Optional.of(teams));
        when(secretStore.readSecret("sn")).thenReturn("https://teams.example.com/x");

        IntegrationNotificationData raw = new IntegrationNotificationData(
                null, null, null, null, null, json("{\"foo\":\"bar\"}"));
        ApiException ex = catchThrowableOfType(
                () -> service.sendNotification(request(IntegrationProvider.TEAMS, raw)),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(400);
    }
}
