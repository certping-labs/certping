// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import com.certmanagement.messaging.model.TargetType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AzureAgcResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final AzureAgcResultMerger merger = new AzureAgcResultMerger(objectMapper);

    @Test
    void supportedTargetTypes_returnsAgcOnly() {
        assertThat(merger.supportedTargetTypes()).containsExactly(TargetType.AZURE_APP_GW_CONTAINERS);
    }

    @Test
    void merge_buildsResultWithAppliedSecrets() throws Exception {
        JsonNode current = objectMapper.createObjectNode();
        JsonNode fromAgent = objectMapper.readTree(
                "{\"clusterName\":\"aks-prod\",\"agcNamespace\":\"agc-system\"," +
                "\"appliedSecrets\":[" +
                "{\"namespace\":\"app-prod\",\"secretName\":\"api-tls\",\"resourceVersion\":\"1234\"}" +
                "]}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("clusterName").asString()).isEqualTo("aks-prod");
        assertThat(merged.get("agcNamespace").asString()).isEqualTo("agc-system");
        assertThat(merged.get("appliedSecrets").size()).isEqualTo(1);
        assertThat(merged.get("appliedSecrets").get(0).get("secretName").asString()).isEqualTo("api-tls");
    }

    @Test
    void merge_replacesAppliedSecretsOnEachDeploy() throws Exception {
        JsonNode current = objectMapper.readTree(
                "{\"appliedSecrets\":[{\"namespace\":\"old\",\"secretName\":\"old-tls\"}]}");
        JsonNode fromAgent = objectMapper.readTree(
                "{\"appliedSecrets\":[{\"namespace\":\"new\",\"secretName\":\"new-tls\"}]}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("appliedSecrets").size()).isEqualTo(1);
        assertThat(merged.get("appliedSecrets").get(0).get("namespace").asString()).isEqualTo("new");
    }

    @Test
    void merge_appliedSecretsMissingAndNoOtherFields_returnsCurrentUnchanged() throws Exception {
        // Today's agent returns nothing — verify the merger is a safe no-op (no envelope churn).
        JsonNode current = objectMapper.readTree(
                "{\"appliedSecrets\":[{\"namespace\":\"keep\"}]}");
        JsonNode fromAgent = objectMapper.readTree("{}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged).isSameAs(current);
    }

    @Test
    void merge_appliedSecretsMissingButClusterNameProvided_overlaysOnlyClusterName() throws Exception {
        JsonNode current = objectMapper.readTree(
                "{\"appliedSecrets\":[{\"namespace\":\"keep\"}]}");
        JsonNode fromAgent = objectMapper.readTree("{\"clusterName\":\"aks-new\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("clusterName").asString()).isEqualTo("aks-new");
        // existing appliedSecrets preserved
        assertThat(merged.get("appliedSecrets").size()).isEqualTo(1);
    }

    @Test
    void merge_appliedSecretsEmptyArray_preservesExisting() throws Exception {
        JsonNode current = objectMapper.readTree(
                "{\"appliedSecrets\":[{\"namespace\":\"keep\"}]}");
        JsonNode fromAgent = objectMapper.readTree("{\"appliedSecrets\":[]}");

        JsonNode merged = merger.merge(current, fromAgent);

        // No fields changed (empty array isn't a real overlay) — returns current unchanged
        assertThat(merged).isSameAs(current);
    }

    @Test
    void merge_blankClusterName_doesNotOverlay() throws Exception {
        JsonNode current = objectMapper.readTree("{\"clusterName\":\"keep\"}");
        JsonNode fromAgent = objectMapper.readTree(
                "{\"clusterName\":\"   \",\"appliedSecrets\":[{\"namespace\":\"a\"}]}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("clusterName").asString()).isEqualTo("keep");
        assertThat(merged.get("appliedSecrets").size()).isEqualTo(1);
    }

    @Test
    void merge_nullFromAgent_returnsCurrent() {
        JsonNode current = objectMapper.createObjectNode().put("clusterName", "x");
        JsonNode merged = merger.merge(current, null);
        assertThat(merged).isSameAs(current);
    }

    @Test
    void merge_nullCurrent_buildsFreshResult() throws Exception {
        JsonNode fromAgent = objectMapper.readTree(
                "{\"appliedSecrets\":[{\"namespace\":\"app\",\"secretName\":\"tls\"}]}");

        JsonNode merged = merger.merge(null, fromAgent);

        assertThat(merged.get("appliedSecrets").size()).isEqualTo(1);
    }
}
