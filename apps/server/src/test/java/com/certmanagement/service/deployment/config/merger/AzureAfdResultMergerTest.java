// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import com.certmanagement.messaging.model.TargetType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AzureAfdResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final AzureAfdResultMerger merger = new AzureAfdResultMerger(objectMapper);

    @Test
    void supportedTargetTypes_returnsAzureAfdOnly() {
        assertThat(merger.supportedTargetTypes()).containsExactly(TargetType.AZURE_AFD);
    }

    @Test
    void merge_emptyCurrent_buildsResultFromAgent() throws Exception {
        JsonNode current = objectMapper.createObjectNode();
        JsonNode fromAgent = objectMapper.readTree(
                "{\"certificateName\":\"certping-wildcard\",\"secretName\":\"certping-afd-secret\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certificateName").asString()).isEqualTo("certping-wildcard");
        assertThat(merged.get("secretName").asString()).isEqualTo("certping-afd-secret");
    }

    @Test
    void merge_overlaysBothFields() throws Exception {
        JsonNode current = objectMapper.readTree(
                "{\"certificateName\":\"old\",\"secretName\":\"old-secret\"}");
        JsonNode fromAgent = objectMapper.readTree(
                "{\"certificateName\":\"new\",\"secretName\":\"new-secret\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certificateName").asString()).isEqualTo("new");
        assertThat(merged.get("secretName").asString()).isEqualTo("new-secret");
    }

    @Test
    void merge_blankSecretName_doesNotOverlay() throws Exception {
        JsonNode current = objectMapper.readTree("{\"secretName\":\"keep-me\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"secretName\":\"   \"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("secretName").asString()).isEqualTo("keep-me");
    }

    @Test
    void merge_nullFromAgent_returnsCurrent() {
        JsonNode current = objectMapper.createObjectNode().put("secretName", "x");
        JsonNode merged = merger.merge(current, null);
        assertThat(merged).isSameAs(current);
    }

    @Test
    void merge_nonObjectFromAgent_returnsCurrent() {
        JsonNode current = objectMapper.createObjectNode().put("secretName", "x");
        JsonNode merged = merger.merge(current, objectMapper.createArrayNode());
        assertThat(merged).isSameAs(current);
    }

    @Test
    void merge_nullCurrent_buildsFreshResult() throws Exception {
        JsonNode fromAgent = objectMapper.readTree(
                "{\"certificateName\":\"cert\",\"secretName\":\"secret\"}");
        JsonNode merged = merger.merge(null, fromAgent);
        assertThat(merged.get("certificateName").asString()).isEqualTo("cert");
        assertThat(merged.get("secretName").asString()).isEqualTo("secret");
    }
}
