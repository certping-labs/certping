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

class GcpCertManagerTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void validate_emptyTargets_normalizesToEmptyObject() throws Exception {
        GcpCertManagerTargetsValidator validator = new GcpCertManagerTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.isObject()).isTrue();
        assertThat(result.size()).isEqualTo(0);
    }

    @Test
    void validate_certificateName_passesThroughTrimmed() throws Exception {
        GcpCertManagerTargetsValidator validator = new GcpCertManagerTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"certificateName\":\"  my-cert  \"}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("certificateName").asString()).isEqualTo("my-cert");
    }

    @Test
    void validate_blankCertificateName_omittedFromOutput() throws Exception {
        GcpCertManagerTargetsValidator validator = new GcpCertManagerTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"certificateName\":\"   \"}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.has("certificateName")).isFalse();
    }

    @Test
    void validate_nonStringCertificateName_throws() throws Exception {
        GcpCertManagerTargetsValidator validator = new GcpCertManagerTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"certificateName\":123}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("certificateName");
    }

    @Test
    void validate_unknownFields_silentlyDropped() throws Exception {
        GcpCertManagerTargetsValidator validator = new GcpCertManagerTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"random\":\"ignored\"}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.size()).isEqualTo(0);
    }
}
