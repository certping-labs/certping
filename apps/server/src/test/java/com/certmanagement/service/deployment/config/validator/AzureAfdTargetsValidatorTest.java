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

class AzureAfdTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void validate_acceptsDomainInScope() throws Exception {
        AzureAfdTargetsValidator validator = new AzureAfdTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"customDomains\":[\"api-example-com\",\"www-example-com\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"certificateName\":\"certping-www\",\"secretName\":\"certping-www-secret\"," +
                "\"domainNames\":[\"api-example-com\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("certificateName").asString()).isEqualTo("certping-www");
        assertThat(result.get("secretName").asString()).isEqualTo("certping-www-secret");
        assertThat(result.get("domainNames").isArray()).isTrue();
        assertThat(result.get("domainNames").get(0).asString()).isEqualTo("api-example-com");
    }

    @Test
    void validate_rejectsDomainNotInScope() throws Exception {
        AzureAfdTargetsValidator validator = new AzureAfdTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"customDomains\":[\"api-example-com\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[\"unknown\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not in the credential's scope.customDomains");
    }

    @Test
    void validate_acceptsWhenNoScopeCustomDomains() throws Exception {
        AzureAfdTargetsValidator validator = new AzureAfdTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[\"any-domain\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("domainNames").get(0).asString()).isEqualTo("any-domain");
    }

    @Test
    void validate_rejectsDuplicateDomains() throws Exception {
        AzureAfdTargetsValidator validator = new AzureAfdTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[\"d1\",\"d1\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void validate_rejectsEmptyDomainNames() throws Exception {
        AzureAfdTargetsValidator validator = new AzureAfdTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty");
    }

    @Test
    void validate_rejectsMissingCertificateName() throws Exception {
        AzureAfdTargetsValidator validator = new AzureAfdTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"secretName\":\"s\",\"domainNames\":[\"d1\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("certificateName");
    }

    @Test
    void validate_rejectsMissingSecretName() throws Exception {
        AzureAfdTargetsValidator validator = new AzureAfdTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree(
                "{\"certificateName\":\"c\",\"domainNames\":[\"d1\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("secretName");
    }

    @Test
    void validate_acceptsMultipleDomains() throws Exception {
        AzureAfdTargetsValidator validator = new AzureAfdTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"customDomains\":[\"d1\",\"d2\",\"d3\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[\"d1\",\"d2\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("domainNames").size()).isEqualTo(2);
    }
}
