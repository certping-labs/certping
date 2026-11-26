// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CloudflareResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void merge_overlaysCertId() throws Exception {
        CloudflareResultMerger merger = new CloudflareResultMerger(objectMapper);
        JsonNode current = objectMapper.readTree("{\"certId\":\"old-id\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"certId\":\"new-id\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certId").asString()).isEqualTo("new-id");
    }

    @Test
    void merge_firstDeploy_setsCertId() throws Exception {
        CloudflareResultMerger merger = new CloudflareResultMerger(objectMapper);
        JsonNode fromAgent = objectMapper.readTree("{\"certId\":\"first-id\"}");

        JsonNode merged = merger.merge(null, fromAgent);

        assertThat(merged.get("certId").asString()).isEqualTo("first-id");
    }

    @Test
    void merge_missingCertId_preservesCurrent() throws Exception {
        CloudflareResultMerger merger = new CloudflareResultMerger(objectMapper);
        JsonNode current = objectMapper.readTree("{\"certId\":\"existing-id\"}");
        JsonNode fromAgent = objectMapper.readTree("{}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certId").asString()).isEqualTo("existing-id");
    }
}
