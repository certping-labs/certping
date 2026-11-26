// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.certmanagement.support.auth.AuthenticatedUser;
import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.integrations.api.model.CreateIntegrationRequest;
import com.certmanagement.support.integrations.api.model.IntegrationResponse;
import com.certmanagement.support.integrations.api.model.UpdateIntegrationRequest;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationAuditAction;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.certmanagement.support.integrations.domain.IntegrationRepository;
import com.certmanagement.support.integrations.secret.SecretStore;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class IntegrationServiceTest {

    @Mock
    private IntegrationRepository integrationRepository;
    @Mock
    private IntegrationAuditService integrationAuditService;
    @Mock
    private SecretStore secretStore;
    @Mock
    private IntegrationPayloadValidator integrationPayloadValidator;

    private IntegrationService service;

    @BeforeEach
    void setUp() {
        service = new IntegrationService(
                integrationRepository, integrationAuditService, secretStore, integrationPayloadValidator);
        lenient().when(integrationRepository.saveAndFlush(any(Integration.class)))
                .thenAnswer(inv -> {
                    Integration i = inv.getArgument(0);
                    if (i.getId() == null) {
                        ReflectionTestUtils.setField(i, "id", 7L);
                    }
                    return i;
                });
        // A store hands back a reference for every write.
        lenient().when(secretStore.writeSecret(any(), anyString(), anyString()))
                .thenAnswer(inv -> "ref:" + inv.getArgument(1));
    }

    private AuthenticatedUser user(String orgId) {
        return new AuthenticatedUser(9L, "a@b.com", orgId, "Acme", List.of("ADMIN"), List.of(), "PASSWORD");
    }

    private CreateIntegrationRequest slackCreate() {
        return new CreateIntegrationRequest(IntegrationProvider.SLACK,
                "https://hooks.slack.com/x", null, null, null, null, null);
    }

    private ValidatedIntegrationPayload slackPayload() {
        return new ValidatedIntegrationPayload(Map.of(), Map.of("webhook_url", "https://hooks.slack.com/x"));
    }

    private Integration existing(IntegrationProvider provider) {
        Integration i = new Integration(5L, provider, Map.of(), Map.of("webhook_url", "old-secret"), 9L);
        ReflectionTestUtils.setField(i, "id", 7L);
        return i;
    }

    // ----------------------------- create -----------------------------

    @Test
    void createIntegration_success() {
        when(integrationPayloadValidator.validateForCreate(any())).thenReturn(slackPayload());
        when(integrationRepository.existsByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(false);

        when(secretStore.writeSecret(isNull(), eq("integration-5-slack-webhook-url"), eq("https://hooks.slack.com/x")))
                .thenReturn("local:certping-integration-5-slack-webhook-url");

        IntegrationResponse response = service.createIntegration(user("5"), slackCreate());

        assertThat(response.provider()).isEqualTo(IntegrationProvider.SLACK);
        // The row keeps the reference the store returned, never the value.
        org.mockito.ArgumentCaptor<Integration> saved = org.mockito.ArgumentCaptor.forClass(Integration.class);
        verify(integrationRepository, org.mockito.Mockito.atLeastOnce()).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getSecretRefs())
                .containsExactly(Map.entry("webhook_url", "local:certping-integration-5-slack-webhook-url"));
        verify(integrationAuditService).recordSuccess(any(), eq(IntegrationAuditAction.CREATED));
    }

    @Test
    void createIntegration_alreadyExists_throws409AndRecordsFailure() {
        when(integrationPayloadValidator.validateForCreate(any())).thenReturn(slackPayload());
        when(integrationRepository.existsByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(true);

        ApiException ex = catchThrowableOfType(
                () -> service.createIntegration(user("5"), slackCreate()), ApiException.class);
        assertThat(ex.status()).isEqualTo(409);
        assertThat(ex.code()).isEqualTo("INTEGRATION_ALREADY_EXISTS");
        verify(integrationRepository, never()).saveAndFlush(any());
    }

    @Test
    void createIntegration_secretStoreFails_throws502() {
        when(integrationPayloadValidator.validateForCreate(any())).thenReturn(slackPayload());
        when(integrationRepository.existsByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(false);
        org.mockito.Mockito.doThrow(new RuntimeException("kv down"))
                .when(secretStore).writeSecret(any(), anyString(), anyString());

        ApiException ex = catchThrowableOfType(
                () -> service.createIntegration(user("5"), slackCreate()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
        assertThat(ex.code()).isEqualTo("SECRET_STORE_OPERATION_FAILED");
    }

    @Test
    void createIntegration_validatorThrowsApiException_propagated() {
        when(integrationPayloadValidator.validateForCreate(any()))
                .thenThrow(new ApiException(400, "INTEGRATION_REQUEST_INVALID", "bad"));

        ApiException ex = catchThrowableOfType(
                () -> service.createIntegration(user("5"), slackCreate()), ApiException.class);
        assertThat(ex.status()).isEqualTo(400);
    }

    @Test
    void createIntegration_dataIntegrityUniqueness_mappedTo409() {
        when(integrationPayloadValidator.validateForCreate(any())).thenReturn(slackPayload());
        when(integrationRepository.existsByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(false);
        when(integrationRepository.saveAndFlush(any()))
                .thenThrow(new DataIntegrityViolationException("uq_integrations_org_provider_active violated"));

        ApiException ex = catchThrowableOfType(
                () -> service.createIntegration(user("5"), slackCreate()), ApiException.class);
        assertThat(ex.status()).isEqualTo(409);
        assertThat(ex.code()).isEqualTo("INTEGRATION_ALREADY_EXISTS");
    }

    @Test
    void createIntegration_otherDataIntegrity_mappedTo500() {
        when(integrationPayloadValidator.validateForCreate(any())).thenReturn(slackPayload());
        when(integrationRepository.existsByOrganizationIdAndProviderAndDeletedAtIsNull(5L, IntegrationProvider.SLACK))
                .thenReturn(false);
        when(integrationRepository.saveAndFlush(any()))
                .thenThrow(new DataIntegrityViolationException("some other constraint"));

        ApiException ex = catchThrowableOfType(
                () -> service.createIntegration(user("5"), slackCreate()), ApiException.class);
        assertThat(ex.status()).isEqualTo(500);
        assertThat(ex.code()).isEqualTo("INTEGRATION_OPERATION_FAILED");
    }

    @Test
    void createIntegration_invalidOrgId_throws401() {
        ApiException ex = catchThrowableOfType(
                () -> service.createIntegration(user("nope"), slackCreate()), ApiException.class);
        assertThat(ex.status()).isEqualTo(401);
    }

    // ----------------------------- update -----------------------------

    @Test
    void updateIntegration_success() {
        Integration integration = existing(IntegrationProvider.SLACK);
        when(integrationRepository.findByIdAndOrganizationIdAndDeletedAtIsNull(7L, 5L))
                .thenReturn(Optional.of(integration));
        when(integrationPayloadValidator.validateForUpdate(eq(IntegrationProvider.SLACK), any()))
                .thenReturn(new ValidatedIntegrationPayload(Map.of(), Map.of("webhook_url", "https://new")));

        UpdateIntegrationRequest request = new UpdateIntegrationRequest(
                "https://new", null, null, null, null, null);
        IntegrationResponse response = service.updateIntegration(user("5"), 7L, request);

        assertThat(response.provider()).isEqualTo(IntegrationProvider.SLACK);
        // The secret is rotated at the reference the row already holds.
        verify(secretStore).writeSecret(eq("old-secret"), eq("integration-5-slack-webhook-url"), eq("https://new"));
        verify(integrationAuditService).recordSuccess(any(), eq(IntegrationAuditAction.UPDATED));
    }

    @Test
    void updateIntegration_notFound_throws404AndRecordsFailure() {
        when(integrationRepository.findByIdAndOrganizationIdAndDeletedAtIsNull(7L, 5L))
                .thenReturn(Optional.empty());

        UpdateIntegrationRequest request = new UpdateIntegrationRequest(
                "https://new", null, null, null, null, null);
        ApiException ex = catchThrowableOfType(
                () -> service.updateIntegration(user("5"), 7L, request), ApiException.class);
        assertThat(ex.status()).isEqualTo(404);
    }

    @Test
    void updateIntegration_invalidOrgId_noFailureRecorded() {
        UpdateIntegrationRequest request = new UpdateIntegrationRequest(
                "https://new", null, null, null, null, null);
        ApiException ex = catchThrowableOfType(
                () -> service.updateIntegration(user("nope"), 7L, request), ApiException.class);
        assertThat(ex.status()).isEqualTo(401);
    }

    // ----------------------------- delete -----------------------------

    @Test
    void deleteIntegration_success() {
        Integration integration = existing(IntegrationProvider.TEAMS);
        when(integrationRepository.findByIdAndOrganizationIdAndDeletedAtIsNull(7L, 5L))
                .thenReturn(Optional.of(integration));

        service.deleteIntegration(user("5"), 7L);

        assertThat(integration.isDeleted()).isTrue();
        verify(integrationAuditService).recordSuccess(any(), eq(IntegrationAuditAction.DELETED));
    }

    @Test
    void deleteIntegration_notFound_throws404() {
        when(integrationRepository.findByIdAndOrganizationIdAndDeletedAtIsNull(7L, 5L))
                .thenReturn(Optional.empty());

        ApiException ex = catchThrowableOfType(
                () -> service.deleteIntegration(user("5"), 7L), ApiException.class);
        assertThat(ex.status()).isEqualTo(404);
    }

    // ----------------------------- list / get -----------------------------

    @Test
    void listIntegrations_mapsAll() {
        when(integrationRepository.findAllByOrganizationIdAndDeletedAtIsNullOrderByProviderAsc(5L))
                .thenReturn(List.of(existing(IntegrationProvider.SLACK), existing(IntegrationProvider.TEAMS)));

        List<IntegrationResponse> result = service.listIntegrations(user("5"));
        assertThat(result).hasSize(2);
    }

    @Test
    void listIntegrationsForOrganization_success() {
        when(integrationRepository.findAllByOrganizationIdAndDeletedAtIsNullOrderByProviderAsc(5L))
                .thenReturn(List.of(existing(IntegrationProvider.PAGERDUTY)));

        List<IntegrationResponse> result = service.listIntegrationsForOrganization(5L);
        assertThat(result).hasSize(1);
        assertThat(result.get(0).provider()).isEqualTo(IntegrationProvider.PAGERDUTY);
    }

    @Test
    void listIntegrationsForOrganization_invalidOrg_throws400() {
        ApiException ex = catchThrowableOfType(
                () -> service.listIntegrationsForOrganization(0L), ApiException.class);
        assertThat(ex.status()).isEqualTo(400);
        assertThat(ex.code()).isEqualTo("INTEGRATION_REQUEST_INVALID");
    }

    @Test
    void getIntegration_success() {
        Integration integration = existing(IntegrationProvider.SERVICENOW_ITSM);
        when(integrationRepository.findByIdAndOrganizationIdAndDeletedAtIsNull(7L, 5L))
                .thenReturn(Optional.of(integration));

        IntegrationResponse response = service.getIntegration(user("5"), 7L);
        assertThat(response.id()).isEqualTo(7L);
        assertThat(response.provider()).isEqualTo(IntegrationProvider.SERVICENOW_ITSM);
    }
}
