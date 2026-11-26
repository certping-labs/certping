// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import tools.jackson.databind.JsonNode;
import com.certmanagement.exception.BadRequestException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class F5TargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void validate_emptyTargets_returnsEmptyObject() throws Exception {
        F5TargetsValidator validator = new F5TargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"partition\":\"Common\"}")
                .build();
        JsonNode targets = objectMapper.readTree("{}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.isObject()).isTrue();
        assertThat(result.isEmpty()).isTrue();
    }

    @Test
    void validate_nullTargets_returnsEmptyObject() {
        F5TargetsValidator validator = new F5TargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"partition\":\"Common\"}")
                .build();

        JsonNode result = validator.validate(null, cred);

        assertThat(result.isObject()).isTrue();
        assertThat(result.isEmpty()).isTrue();
    }

    @Test
    void validate_certBaseName_passesThroughTrimmed() throws Exception {
        F5TargetsValidator validator = new F5TargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"certBaseName\":\"  certping-www  \"}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("certBaseName").asString()).isEqualTo("certping-www");
    }

    @Test
    void validate_blankCertBaseName_omittedFromOutput() throws Exception {
        F5TargetsValidator validator = new F5TargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"certBaseName\":\"   \"}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.has("certBaseName")).isFalse();
    }

    @Test
    void validate_nonStringCertBaseName_throws() throws Exception {
        F5TargetsValidator validator = new F5TargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();
        JsonNode targets = objectMapper.readTree("{\"certBaseName\":42}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("certBaseName");
    }
}
