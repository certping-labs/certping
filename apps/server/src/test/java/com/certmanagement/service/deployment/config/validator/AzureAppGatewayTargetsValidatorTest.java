// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AzureAppGatewayTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void validate_acceptsListenerInScope() throws Exception {
        AzureAppGatewayTargetsValidator validator = new AzureAppGatewayTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"listeners\":[\"https-443\",\"https-8443\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"sslCertName\":\"certping-www\",\"listenerNames\":[\"https-443\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("sslCertName").asString()).isEqualTo("certping-www");
        assertThat(result.get("listenerNames").isArray()).isTrue();
        assertThat(result.get("listenerNames").get(0).asString()).isEqualTo("https-443");
    }

    @Test
    void validate_rejectsListenerNotInScope() throws Exception {
        AzureAppGatewayTargetsValidator validator = new AzureAppGatewayTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"listeners\":[\"https-443\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"sslCertName\":\"c\",\"listenerNames\":[\"unknown\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not in the credential's scope.listeners");
    }

    @Test
    void validate_acceptsWhenNoScopeListeners() throws Exception {
        AzureAppGatewayTargetsValidator validator = new AzureAppGatewayTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"sslCertName\":\"c\",\"listenerNames\":[\"any-listener\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("listenerNames").get(0).asString()).isEqualTo("any-listener");
    }

    @Test
    void validate_rejectsDuplicateListeners() throws Exception {
        AzureAppGatewayTargetsValidator validator = new AzureAppGatewayTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"sslCertName\":\"c\",\"listenerNames\":[\"l1\",\"l1\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void validate_rejectsEmptyListenerNames() throws Exception {
        AzureAppGatewayTargetsValidator validator = new AzureAppGatewayTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"sslCertName\":\"c\",\"listenerNames\":[]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty");
    }

    @Test
    void validate_rejectsMissingSslCertName() throws Exception {
        AzureAppGatewayTargetsValidator validator = new AzureAppGatewayTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"listenerNames\":[\"https-443\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("sslCertName");
    }

    @Test
    void validate_acceptsMultipleListeners() throws Exception {
        AzureAppGatewayTargetsValidator validator = new AzureAppGatewayTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"listeners\":[\"https-443\",\"https-8443\",\"https-9443\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"sslCertName\":\"c\",\"listenerNames\":[\"https-443\",\"https-8443\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("listenerNames").size()).isEqualTo(2);
    }
}
