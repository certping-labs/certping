// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import com.certmanagement.messaging.model.TargetType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AzureAppGatewayResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final AzureAppGatewayResultMerger merger = new AzureAppGatewayResultMerger(objectMapper);

    @Test
    void supportedTargetTypes_returnsAzureAppGwOnly() {
        assertThat(merger.supportedTargetTypes()).containsExactly(TargetType.AZURE_APP_GW);
    }

    @Test
    void merge_emptyCurrent_buildsResultFromAgent() throws Exception {
        JsonNode current = objectMapper.createObjectNode();
        JsonNode fromAgent = objectMapper.readTree(
                "{\"certificateName\":\"certping-wildcard\",\"keyVaultSecretId\":\"https://kv.vault.azure.net/secrets/cert/v1\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certificateName").asString()).isEqualTo("certping-wildcard");
        assertThat(merged.get("keyVaultSecretId").asString()).isEqualTo("https://kv.vault.azure.net/secrets/cert/v1");
    }

    @Test
    void merge_overlaysBothFields() throws Exception {
        JsonNode current = objectMapper.readTree(
                "{\"certificateName\":\"old\",\"keyVaultSecretId\":\"old-id\"}");
        JsonNode fromAgent = objectMapper.readTree(
                "{\"certificateName\":\"new\",\"keyVaultSecretId\":\"new-id\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certificateName").asString()).isEqualTo("new");
        assertThat(merged.get("keyVaultSecretId").asString()).isEqualTo("new-id");
    }

    @Test
    void merge_blankCertificateName_doesNotOverlay() throws Exception {
        JsonNode current = objectMapper.readTree("{\"certificateName\":\"keep\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"certificateName\":\"\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certificateName").asString()).isEqualTo("keep");
    }

    @Test
    void merge_nullFromAgent_returnsCurrent() {
        JsonNode current = objectMapper.createObjectNode().put("certificateName", "x");
        JsonNode merged = merger.merge(current, null);
        assertThat(merged).isSameAs(current);
    }

    @Test
    void merge_nonObjectFromAgent_returnsCurrent() {
        JsonNode current = objectMapper.createObjectNode().put("certificateName", "x");
        JsonNode merged = merger.merge(current, objectMapper.createArrayNode());
        assertThat(merged).isSameAs(current);
    }

    @Test
    void merge_nullCurrent_buildsFreshResult() throws Exception {
        JsonNode fromAgent = objectMapper.readTree(
                "{\"certificateName\":\"cert\",\"keyVaultSecretId\":\"id\"}");
        JsonNode merged = merger.merge(null, fromAgent);
        assertThat(merged.get("certificateName").asString()).isEqualTo("cert");
        assertThat(merged.get("keyVaultSecretId").asString()).isEqualTo("id");
    }
}
