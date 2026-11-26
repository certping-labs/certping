// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AkamaiTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void validate_emptyTargets_returnsEmptyObject() throws Exception {
        AkamaiTargetsValidator validator = new AkamaiTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"enrollmentId\":\"12345\"}")
                .build();
        JsonNode targets = objectMapper.readTree("{}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.isObject()).isTrue();
        assertThat(result.isEmpty()).isTrue();
    }

    @Test
    void validate_nullTargets_returnsEmptyObject() {
        AkamaiTargetsValidator validator = new AkamaiTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"enrollmentId\":\"12345\"}")
                .build();

        JsonNode result = validator.validate(null, cred);

        assertThat(result.isObject()).isTrue();
        assertThat(result.isEmpty()).isTrue();
    }
}
