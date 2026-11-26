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

class AwsElbTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final AwsElbTargetsValidator validator = new AwsElbTargetsValidator(objectMapper);

    private static final String LISTENER_ARN =
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-lb/123abc/456def";

    @Test
    void validate_acceptsListenerArnWhenInScopeListeners() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"listeners\":[\"" + LISTENER_ARN + "\"]}")
                .build();
        JsonNode targets = objectMapper.readTree("{\"listenerArns\":[\"" + LISTENER_ARN + "\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("listenerArns").get(0).asString()).isEqualTo(LISTENER_ARN);
    }

    @Test
    void validate_rejectsListenerNotInScopeListeners() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"listeners\":[\"" + LISTENER_ARN + "\"]}")
                .build();
        String otherListener = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/other/999abc/888def";
        JsonNode targets = objectMapper.readTree("{\"listenerArns\":[\"" + otherListener + "\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not in the credential's scope.listeners");
    }

    @Test
    void validate_acceptsWhenNoScopeListeners() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")
                .build();
        JsonNode targets = objectMapper.readTree("{\"listenerArns\":[\"" + LISTENER_ARN + "\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("listenerArns").get(0).asString()).isEqualTo(LISTENER_ARN);
    }

    @Test
    void validate_rejectsDuplicateListenerArns() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .configJson("{\"listeners\":[\"" + LISTENER_ARN + "\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"listenerArns\":[\"" + LISTENER_ARN + "\",\"" + LISTENER_ARN + "\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Duplicate");
    }
}
