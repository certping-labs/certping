// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AzureKvTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final AzureKvTargetsValidator validator = new AzureKvTargetsValidator(objectMapper);

    private CredentialReferenceEntity cred(String configJson) {
        return CredentialReferenceEntity.builder().configJson(configJson).build();
    }

    @Test
    void validate_flatCertificateName_accepted() throws Exception {
        JsonNode targets = objectMapper.readTree("{\"certificateName\":\"wildcard-prod\"}");
        JsonNode result = validator.validate(targets, cred("{\"authMode\":\"SERVICE_PRINCIPAL\",\"vaultUri\":\"https://kv.vault.azure.net/\"}"));
        assertThat(result.get("certificateName").asString()).isEqualTo("wildcard-prod");
    }

    @Test
    void validate_missingCertificateName_acceptedAsEmpty() throws Exception {
        // certificateName is now optional — adapter auto-derives from cert domain.
        JsonNode targets = objectMapper.readTree("{}");
        JsonNode result = validator.validate(targets, cred(null));
        assertThat(result.has("certificateName")).isFalse();
    }

    @Test
    void validate_blankCertificateName_acceptedAsEmpty() throws Exception {
        JsonNode targets = objectMapper.readTree("{\"certificateName\":\"  \"}");
        JsonNode result = validator.validate(targets, cred(null));
        assertThat(result.has("certificateName")).isFalse();
    }

    @Test
    void validate_invalidCertificateName_throws() throws Exception {
        JsonNode targets = objectMapper.readTree("{\"certificateName\":\"bad name!\"}");
        assertThatThrownBy(() -> validator.validate(targets, cred(null)))
                .hasMessageContaining("alphanumeric");
    }

    @Test
    void validate_nullTargets_acceptedAsEmpty() {
        // null targets → empty object (operator can omit if they want auto-derived).
        JsonNode result = validator.validate(null, cred(null));
        assertThat(result.has("certificateName")).isFalse();
        assertThat(result.size()).isEqualTo(0);
    }

    @Test
    void validate_normalizesAndTrims() throws Exception {
        JsonNode targets = objectMapper.readTree("{\"certificateName\":\" api-example-com \",\"extra\":\"ignored\"}");
        JsonNode result = validator.validate(targets, cred(null));
        assertThat(result.get("certificateName").asString()).isEqualTo("api-example-com");
        assertThat(result.has("extra")).isFalse();
    }

    @Test
    void validate_nonStringCertificateName_throws() throws Exception {
        JsonNode targets = objectMapper.readTree("{\"certificateName\":123}");
        assertThatThrownBy(() -> validator.validate(targets, cred(null)))
                .hasMessageContaining("string");
    }
}
