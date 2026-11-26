// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.CaProvider;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JSON contract tests for revocation DTOs (server <-> agent).
 */
class CertRevocationMessageJsonTest {

    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = JsonMapper.builderWithJackson2Defaults().build();
    }

    @Test
    void certRevocationCommand_roundTrip_withUserId() throws Exception {
        String json = """
                {
                  "requestId": "r1",
                  "correlationId": "c1",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "caProvider": "LETS_ENCRYPT",
                  "certSecretHandle": "https://kv/secrets/cert",
                  "revocationReason": "KEY_COMPROMISE",
                  "requestedAt": "2026-01-01T00:00:00Z",
                  "userId": 123
                }
                """;

        CertRevocationMessage msg = mapper.readValue(json, CertRevocationMessage.class);
        assertThat(msg.getOrganizationId()).isEqualTo("organization-1");
        assertThat(msg.getCaProvider()).isEqualTo(CaProvider.LETS_ENCRYPT);
        assertThat(msg.getUserId()).isEqualTo(123);

        String out = mapper.writeValueAsString(msg);
        CertRevocationMessage again = mapper.readValue(out, CertRevocationMessage.class);
        assertThat(again.getCertificateXref()).isEqualTo("xref-1");
        assertThat(again.getUserId()).isEqualTo(123);
    }

    @Test
    void certRevocationCommand_userIdCanBeNull() throws Exception {
        String json = """
                {
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "caProvider": "LETS_ENCRYPT",
                  "certSecretHandle": "https://kv/secrets/cert",
                  "revocationReason": "UNSPECIFIED",
                  "userId": null
                }
                """;

        CertRevocationMessage msg = mapper.readValue(json, CertRevocationMessage.class);
        assertThat(msg.getUserId()).isNull();
        assertThat(msg.getCertificateXref()).isEqualTo("xref-1");
    }

    @Test
    void certRevocationCommand_unknownJsonPropertiesIgnored() throws Exception {
        String json = """
                {
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "caProvider": "LETS_ENCRYPT",
                  "certSecretHandle": "https://kv/secrets/cert",
                  "futureField": "ignore-me"
                }
                """;

        CertRevocationMessage msg = mapper.readValue(json, CertRevocationMessage.class);
        assertThat(msg.getCertificateXref()).isEqualTo("xref-1");
    }
}
