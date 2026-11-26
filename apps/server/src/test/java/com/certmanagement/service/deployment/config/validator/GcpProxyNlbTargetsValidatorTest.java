// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GcpProxyNlbTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void validate_acceptsEmptyTargets() throws Exception {
        GcpProxyNlbTargetsValidator validator = new GcpProxyNlbTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"targetSslProxy\":\"ssl-proxy-1\"}")
                .build();
        JsonNode targets = objectMapper.readTree("{}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.isObject()).isTrue();
        assertThat(result.isEmpty()).isTrue();
    }

    @Test
    void validate_acceptsNullTargets() {
        GcpProxyNlbTargetsValidator validator = new GcpProxyNlbTargetsValidator(objectMapper);
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder().build();

        JsonNode result = validator.validate(null, cred);

        assertThat(result.isObject()).isTrue();
    }
}
