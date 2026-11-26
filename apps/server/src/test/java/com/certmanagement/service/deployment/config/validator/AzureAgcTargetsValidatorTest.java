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

class AzureAgcTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void validate_acceptsSecretInScope() throws Exception {
        AzureAgcTargetsValidator validator = new AzureAgcTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"secretNamespaces\":[\"app-prod\",\"app-edge\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"secrets\":[{\"namespace\":\"app-prod\",\"secretName\":\"tls-www\"}]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("secrets").isArray()).isTrue();
        assertThat(result.get("secrets").get(0).get("namespace").asString()).isEqualTo("app-prod");
        assertThat(result.get("secrets").get(0).get("secretName").asString()).isEqualTo("tls-www");
    }

    @Test
    void validate_rejectsNamespaceNotInScope() throws Exception {
        AzureAgcTargetsValidator validator = new AzureAgcTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"secretNamespaces\":[\"app-prod\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"secrets\":[{\"namespace\":\"unknown\",\"secretName\":\"tls-1\"}]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not in the credential's scope.secretNamespaces");
    }

    @Test
    void validate_acceptsWhenNoScopeSecretNamespaces() throws Exception {
        AzureAgcTargetsValidator validator = new AzureAgcTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"secrets\":[{\"namespace\":\"any-ns\",\"secretName\":\"tls-1\"}]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("secrets").get(0).get("namespace").asString()).isEqualTo("any-ns");
    }

    @Test
    void validate_rejectsDuplicateSecretRefs() throws Exception {
        AzureAgcTargetsValidator validator = new AzureAgcTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"secrets\":[" +
                "{\"namespace\":\"app\",\"secretName\":\"tls-1\"}," +
                "{\"namespace\":\"app\",\"secretName\":\"tls-1\"}" +
                "]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void validate_rejectsEmptySecrets() throws Exception {
        AzureAgcTargetsValidator validator = new AzureAgcTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"secrets\":[]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty");
    }

    @Test
    void validate_acceptsMultipleSecretsAcrossNamespaces() throws Exception {
        AzureAgcTargetsValidator validator = new AzureAgcTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"secretNamespaces\":[\"app-prod\",\"app-edge\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"secrets\":[" +
                "{\"namespace\":\"app-prod\",\"secretName\":\"tls-www\"}," +
                "{\"namespace\":\"app-prod\",\"secretName\":\"tls-api\"}," +
                "{\"namespace\":\"app-edge\",\"secretName\":\"tls-www\"}" +
                "]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("secrets").size()).isEqualTo(3);
    }

    @Test
    void validate_rejectsMissingSecretName() throws Exception {
        AzureAgcTargetsValidator validator = new AzureAgcTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"secrets\":[{\"namespace\":\"app-prod\"}]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("secretName");
    }
}
