// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AkamaiResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void merge_movesPriorLastChangeIntoHistory() throws Exception {
        AkamaiResultMerger merger = new AkamaiResultMerger(objectMapper);
        JsonNode current = objectMapper.readTree("{\"lastChange\":{\"id\":1},\"history\":[{\"id\":0},{\"id\":-1},{\"id\":-2},{\"id\":-3},{\"id\":-4}]}" );
        JsonNode fromAgent = objectMapper.readTree("{\"lastChange\":{\"id\":2}}" );

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("lastChange").get("id").asInt()).isEqualTo(2);
        assertThat(merged.get("history").isArray()).isTrue();
        assertThat(merged.get("history").size()).isEqualTo(5);
        assertThat(merged.get("history").get(0).get("id").asInt()).isEqualTo(1);
    }
}
