// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertRenewalMessageJsonTest {

    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = JsonMapper.builderWithJackson2Defaults().build();
    }

    @Test
    void previousCertSecretHandle_deserialisesFromCanonicalFieldName() throws Exception {
        String json = """
                {
                  "requestId": "req-1",
                  "certificateXref": "cert-1",
                  "domain": "example.com",
                  "caProvider": "LETS_ENCRYPT",
                  "previousCertSecretHandle": "https://kv.vault.azure.net/secrets/cert-old/abc"
                }
                """;

        CertRenewalMessage msg = mapper.readValue(json, CertRenewalMessage.class);

        assertThat(msg.getPreviousCertSecretHandle())
                .isEqualTo("https://kv.vault.azure.net/secrets/cert-old/abc");
    }
}
