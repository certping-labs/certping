// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DeploymentConfigEnvelopeTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void read_nullOrBlank_returnsEmptyEnvelope() {
        DeploymentConfigEnvelope fromNull = DeploymentConfigEnvelope.read(objectMapper, null);
        DeploymentConfigEnvelope fromBlank = DeploymentConfigEnvelope.read(objectMapper, " ");

        assertThat(fromNull.targets().isObject()).isTrue();
        assertThat(fromNull.result().isObject()).isTrue();
        assertThat(fromBlank.targets().isObject()).isTrue();
        assertThat(fromBlank.result().isObject()).isTrue();
    }

    @Test
    void read_missingFields_returnsEmptyNodes() {
        DeploymentConfigEnvelope envelope = DeploymentConfigEnvelope.read(objectMapper, "{\"foo\":\"bar\"}");

        assertThat(envelope.targets().isObject()).isTrue();
        assertThat(envelope.result().isObject()).isTrue();
    }

    @Test
    void write_includesTargetsAndResult() throws Exception {
        JsonNode targets = objectMapper.readTree("{\"zones\":[{\"zoneId\":\"z1\"}]}" );
        JsonNode result = objectMapper.readTree("{\"certificateName\":\"cert-1\"}");
        DeploymentConfigEnvelope envelope = new DeploymentConfigEnvelope(targets, result);

        String json = envelope.write(objectMapper);
        JsonNode root = objectMapper.readTree(json);

        assertThat(root.get("targets").get("zones").isArray()).isTrue();
        assertThat(root.get("result").get("certificateName").asString()).isEqualTo("cert-1");
    }
}
