// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GcpResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void merge_withObject_returnsIncoming() throws Exception {
        GcpResultMerger merger = new GcpResultMerger();
        JsonNode current = objectMapper.readTree("{\"old\":\"value\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"certificateMapName\":\"map-1\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged).isSameAs(fromAgent);
    }

    @Test
    void merge_withNonObject_returnsCurrent() throws Exception {
        GcpResultMerger merger = new GcpResultMerger();
        JsonNode current = objectMapper.readTree("{\"old\":\"value\"}");
        JsonNode fromAgent = objectMapper.readTree("[1,2,3]");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged).isSameAs(current);
    }
}
