// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.TargetType;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertDeploymentMessageJsonTest {

    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = JsonMapper.builderWithJackson2Defaults().build();
    }

    @Test
    void configJson_isReadAsStringPayload() throws Exception {
        String json = """
                {
                  "requestId": "req-123",
                  "correlationId": "corr-123",
                  "organizationId": "42",
                  "certificateXref": "cert-0001",
                  "domain": "api.example.com",
                  "certSecretHandle": "https://kv/secrets/cert",
                  "targetType": "KUBERNETES_SECRETS",
                  "deploymentCredHandle": null,
                  "requestedAt": "2026-04-29T12:34:56Z",
                  "configJson": "{\\"clusterName\\":\\"prod-cluster\\",\\"nsMaps\\":[{\\"dev\\":\\"example-dev-tls\\"},{\\"prod\\":\\"example-prod-tls\\"}]}"
                }
                """;

        CertDeploymentMessage msg = mapper.readValue(json, CertDeploymentMessage.class);

        assertThat(msg.getTargetType()).isEqualTo(TargetType.KUBERNETES_SECRETS);
        assertThat(msg.getConfigJson())
                .isEqualTo("{\"clusterName\":\"prod-cluster\",\"nsMaps\":[{\"dev\":\"example-dev-tls\"},{\"prod\":\"example-prod-tls\"}]}");
    }
}
