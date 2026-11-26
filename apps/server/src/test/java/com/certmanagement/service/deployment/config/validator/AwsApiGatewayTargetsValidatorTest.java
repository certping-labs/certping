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

class AwsApiGatewayTargetsValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final AwsApiGatewayTargetsValidator validator = new AwsApiGatewayTargetsValidator(objectMapper);

    private static final String DOMAIN = "api.example.com";

    @Test
    void validate_acceptsDomainNameWhenInScopeCustomDomains() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("AWS_API_GW_REST")
                .configJson("{\"customDomains\":[\"" + DOMAIN + "\"]}")
                .build();
        JsonNode targets = objectMapper.readTree("{\"domainNames\":[\"" + DOMAIN + "\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("domainNames").get(0).asString()).isEqualTo(DOMAIN);
    }

    @Test
    void validate_rejectsDomainNotInScopeCustomDomains() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("AWS_API_GW_REST")
                .configJson("{\"customDomains\":[\"" + DOMAIN + "\"]}")
                .build();
        JsonNode targets = objectMapper.readTree("{\"domainNames\":[\"unknown.example.com\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not in the credential's scope.customDomains");
    }

    @Test
    void validate_acceptsWhenNoScopeCustomDomains() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("AWS_API_GW_HTTP")
                .configJson("{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}")
                .build();
        JsonNode targets = objectMapper.readTree("{\"domainNames\":[\"" + DOMAIN + "\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("domainNames").get(0).asString()).isEqualTo(DOMAIN);
    }

    @Test
    void validate_rejectsDuplicateDomainNames() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("AWS_API_GW_REST")
                .configJson("{\"customDomains\":[\"" + DOMAIN + "\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"domainNames\":[\"" + DOMAIN + "\",\"" + DOMAIN + "\"]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void validate_rejectsEmptyDomainNamesList() throws Exception {
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("AWS_API_GW_REST")
                .configJson("{\"customDomains\":[\"" + DOMAIN + "\"]}")
                .build();
        JsonNode targets = objectMapper.readTree("{\"domainNames\":[]}");

        assertThatThrownBy(() -> validator.validate(targets, cred))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty");
    }

    @Test
    void validate_acceptsMultipleDomainNames() throws Exception {
        String domain2 = "api-eu.example.com";
        CredentialReferenceEntity cred = CredentialReferenceEntity.builder()
                .provider("AWS_API_GW_HTTP")
                .configJson("{\"customDomains\":[\"" + DOMAIN + "\",\"" + domain2 + "\"]}")
                .build();
        JsonNode targets = objectMapper.readTree(
                "{\"domainNames\":[\"" + DOMAIN + "\",\"" + domain2 + "\"]}");

        JsonNode result = validator.validate(targets, cred);

        assertThat(result.get("domainNames")).hasSize(2);
        assertThat(result.get("domainNames").get(0).asString()).isEqualTo(DOMAIN);
        assertThat(result.get("domainNames").get(1).asString()).isEqualTo(domain2);
    }
}
