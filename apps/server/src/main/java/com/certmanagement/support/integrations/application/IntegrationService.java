// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IntegrationService {

    private static final Logger log = LoggerFactory.getLogger(IntegrationService.class);

    private final IntegrationRepository integrationRepository;
    /** Writes the integration.* audit row in each change's transaction. */
    private final IntegrationAuditService integrationAuditService;
    private final SecretStore secretStore;
    private final IntegrationPayloadValidator integrationPayloadValidator;

    public IntegrationService(
            IntegrationRepository integrationRepository,
            IntegrationAuditService integrationAuditService,
            SecretStore secretStore,
            IntegrationPayloadValidator integrationPayloadValidator) {
        this.integrationRepository = integrationRepository;
        this.integrationAuditService = integrationAuditService;
        this.secretStore = secretStore;
        this.integrationPayloadValidator = integrationPayloadValidator;
    }

    @Transactional
    public IntegrationResponse createIntegration(AuthenticatedUser user, CreateIntegrationRequest request) {
        long organizationId = organizationId(user);
        try {
            ValidatedIntegrationPayload payload = integrationPayloadValidator.validateForCreate(request);
            if (integrationRepository.existsByOrganizationIdAndProviderAndDeletedAtIsNull(organizationId, request.provider())) {
                throw alreadyExists();
            }

            Map<String, String> secretRefs = storeSecrets(organizationId, request.provider(), payload.secrets(), Map.of());
            Integration saved = integrationRepository.saveAndFlush(new Integration(
                    organizationId,
                    request.provider(),
                    new LinkedHashMap<>(payload.config()),
                    secretRefs,
                    user.userId()));
            Integration persisted = integrationRepository.saveAndFlush(saved);
            integrationAuditService.recordSuccess(persisted, IntegrationAuditAction.CREATED);
            return toResponse(persisted);
        } catch (Exception exception) {
            // Recorded by the endpoint (@AuditFailure), from the failure's type and status only.
            throw translatedException(exception);
        }
    }

    @Transactional
    public IntegrationResponse updateIntegration(AuthenticatedUser user, long integrationId, UpdateIntegrationRequest request) {
        try {
            Integration integration = findActiveIntegration(user, integrationId);
            ValidatedIntegrationPayload payload = integrationPayloadValidator.validateForUpdate(integration.getProvider(), request);

            Map<String, String> secretRefs = storeSecrets(
                    integration.getOrganizationId(),
                    integration.getProvider(),
                    payload.secrets(),
                    integration.getSecretRefs());
            integration.replaceConfiguration(new LinkedHashMap<>(payload.config()), secretRefs, user.userId());
            Integration saved = integrationRepository.saveAndFlush(integration);
            integrationAuditService.recordSuccess(saved, IntegrationAuditAction.UPDATED);
            return toResponse(saved);
        } catch (Exception exception) {
            // Recorded by the endpoint (@AuditFailure), from the failure's type and status only.
            throw translatedException(exception);
        }
    }

    @Transactional
    public void deleteIntegration(AuthenticatedUser user, long integrationId) {
        try {
            Integration integration = findActiveIntegration(user, integrationId);
            integration.softDelete(user.userId());
            Integration saved = integrationRepository.saveAndFlush(integration);
            integrationAuditService.recordSuccess(saved, IntegrationAuditAction.DELETED);
        } catch (Exception exception) {
            // Recorded by the endpoint (@AuditFailure), from the failure's type and status only.
            throw translatedException(exception);
        }
    }

    @Transactional(readOnly = true)
    public List<IntegrationResponse> listIntegrations(AuthenticatedUser user) {
        return integrationRepository.findAllByOrganizationIdAndDeletedAtIsNullOrderByProviderAsc(organizationId(user)).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<IntegrationResponse> listIntegrationsForOrganization(long organizationId) {
        validateOrganizationId(organizationId);
        return integrationRepository.findAllByOrganizationIdAndDeletedAtIsNullOrderByProviderAsc(organizationId).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public IntegrationResponse getIntegration(AuthenticatedUser user, long integrationId) {
        return toResponse(findActiveIntegration(user, integrationId));
    }

    private Integration findActiveIntegration(AuthenticatedUser user, long integrationId) {
        return integrationRepository.findByIdAndOrganizationIdAndDeletedAtIsNull(integrationId, organizationId(user))
                .orElseThrow(() -> new ApiException(404, "INTEGRATION_NOT_FOUND", "Integration not found"));
    }

    private IntegrationResponse toResponse(Integration integration) {
        return new IntegrationResponse(
                integration.getId(),
                integration.getProvider(),
                integration.getStatus(),
                integration.getCreatedAt(),
                integration.getUpdatedAt(),
                integration.getDeletedAt());
    }

    private ApiException translatedException(Exception exception) {
        if (exception instanceof ApiException apiException) {
            return apiException;
        }
        // Only the partial unique index should surface as a 409. Other data-integrity failures
        // indicate bugs or unexpected schema drift and should stay 500s so they get fixed.
        if (exception instanceof org.springframework.dao.DataIntegrityViolationException
                && isActiveIntegrationUniquenessViolation(exception)) {
            return alreadyExists();
        }
        log.error("integration.operation_failed causeType={} message={}", exception.getClass().getName(), exception.getMessage(), exception);
        return new ApiException(500, "INTEGRATION_OPERATION_FAILED", "Integration operation failed");
    }

    private boolean isActiveIntegrationUniquenessViolation(Exception exception) {
        String message = exception.getMessage();
        return message != null && message.contains("uq_integrations_org_provider_active");
    }

    private ApiException alreadyExists() {
        return new ApiException(409, "INTEGRATION_ALREADY_EXISTS", "An active integration for this provider already exists");
    }

    private Map<String, String> storeSecrets(
            long organizationId,
            IntegrationProvider provider,
            Map<String, String> secrets,
            Map<String, String> existingSecretRefs) {
        Map<String, String> secretRefs = new LinkedHashMap<>();
        secrets.forEach((key, value) -> {
            // A secret written before is rotated at its existing reference, so the reference stays
            // stable; a new one is written under a name derived from the organization and provider.
            String existingRef = existingSecretRef(existingSecretRefs, key);
            String secretName = newSecretName(organizationId, provider, key);
            secretRefs.put(key, writeSecretOrThrow(existingRef, secretName, value, provider, key));
        });
        return Map.copyOf(secretRefs);
    }

    private String writeSecretOrThrow(
            String existingRef, String secretName, String secretValue, IntegrationProvider provider, String secretKey) {
        try {
            return secretStore.writeSecret(existingRef, secretName, secretValue);
        } catch (ApiException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            log.error(
                    "integration.secret_store_write_failed provider={} secretKey={} secretName={} causeType={} message={}",
                    providerName(provider),
                    secretKey,
                    secretName,
                    exception.getClass().getName(),
                    exception.getMessage(),
                    exception);
            throw new ApiException(502, "SECRET_STORE_OPERATION_FAILED", "Failed to persist integration secret");
        }
    }

    private String existingSecretRef(Map<String, String> existingSecretRefs, String key) {
        String ref = existingSecretRefs == null ? null : existingSecretRefs.get(key);
        return StringUtils.hasText(ref) ? ref : null;
    }

    private String newSecretName(long organizationId, IntegrationProvider provider, String secretKey) {
        // Lowercase letters, digits and dashes only, which every secret store accepts (Azure Key
        // Vault is the strictest), and the same name for the same organization, provider and key.
        return "integration-" + organizationId + "-" + toSecretNameSegment(provider.name()) + "-" + toSecretNameSegment(secretKey);
    }

    private String toSecretNameSegment(String rawValue) {
        return rawValue.toLowerCase(Locale.ROOT)
                .replace('_', '-')
                .replaceAll("[^a-z0-9-]", "-")
                .replaceAll("-{2,}", "-")
                .replaceAll("(^-+|-+$)", "");
    }

    private String providerName(IntegrationProvider provider) {
        return provider == null ? "UNKNOWN" : provider.name();
    }

    private long organizationId(AuthenticatedUser user) {
        try {
            return Long.parseLong(user.organizationId());
        } catch (NumberFormatException exception) {
            throw new ApiException(401, "AUTH_TOKEN_INVALID", "Authentication failed");
        }
    }

    private void validateOrganizationId(long organizationId) {
        if (organizationId <= 0) {
            throw new ApiException(400, "INTEGRATION_REQUEST_INVALID", "orgId must be positive");
        }
    }
}
