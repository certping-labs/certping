// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class F5ResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void merge_overlaysFlatResult() throws Exception {
        F5ResultMerger merger = new F5ResultMerger(objectMapper);
        JsonNode current = objectMapper.readTree(
                "{\"certName\":\"cert_v1\",\"keyName\":\"cert_v1\",\"version\":1," +
                "\"profilesPatched\":[\"p1\"]}");
        JsonNode fromAgent = objectMapper.readTree(
                "{\"certName\":\"cert_v2\",\"keyName\":\"cert_v2\",\"version\":2," +
                "\"profilesPatched\":[\"p1\",\"p2\"],\"lastSyncedAt\":\"2026-01-01T00:00:00Z\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certName").asString()).isEqualTo("cert_v2");
        assertThat(merged.get("version").asInt()).isEqualTo(2);
        assertThat(merged.get("profilesPatched").size()).isEqualTo(2);
        assertThat(merged.get("lastSyncedAt").asString()).isEqualTo("2026-01-01T00:00:00Z");
    }

    @Test
    void merge_firstDeploy_setsResult() throws Exception {
        F5ResultMerger merger = new F5ResultMerger(objectMapper);
        JsonNode fromAgent = objectMapper.readTree(
                "{\"certName\":\"cert_v1\",\"keyName\":\"cert_v1\",\"version\":1," +
                "\"profilesPatched\":[\"p1\"]}");

        JsonNode merged = merger.merge(null, fromAgent);

        assertThat(merged.get("certName").asString()).isEqualTo("cert_v1");
        assertThat(merged.get("version").asInt()).isEqualTo(1);
    }

    @Test
    void merge_missingCertName_preservesCurrent() throws Exception {
        F5ResultMerger merger = new F5ResultMerger(objectMapper);
        JsonNode current = objectMapper.readTree("{\"certName\":\"cert_v1\"}");
        JsonNode fromAgent = objectMapper.readTree("{}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certName").asString()).isEqualTo("cert_v1");
    }
}
