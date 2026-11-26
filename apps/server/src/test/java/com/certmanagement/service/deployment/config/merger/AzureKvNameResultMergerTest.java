// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AzureKvNameResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final AzureKvNameResultMerger merger = new AzureKvNameResultMerger(objectMapper);

    @Test
    void supportedTargetTypes_isAzureKvOnly() {
        assertThat(merger.supportedTargetTypes())
                .containsExactly(com.certmanagement.messaging.model.TargetType.AZURE_KV);
    }

    @Test
    void merge_flatResult_setsCertificateNameAndVersion() throws Exception {
        JsonNode current = objectMapper.readTree("{\"certificateName\":\"old\",\"version\":\"v0\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"certificateName\":\"wildcard-prod\",\"version\":\"abc123\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certificateName").asString()).isEqualTo("wildcard-prod");
        assertThat(merged.get("version").asString()).isEqualTo("abc123");
    }

    @Test
    void merge_nullCurrent_createsNewNode() throws Exception {
        JsonNode fromAgent = objectMapper.readTree("{\"certificateName\":\"new-cert\",\"version\":\"v1\"}");

        JsonNode merged = merger.merge(null, fromAgent);

        assertThat(merged.get("certificateName").asString()).isEqualTo("new-cert");
        assertThat(merged.get("version").asString()).isEqualTo("v1");
    }

    @Test
    void merge_noVersion_setsOnlyCertificateName() throws Exception {
        JsonNode current = objectMapper.readTree("{\"certificateName\":\"old\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"certificateName\":\"new-cert\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("certificateName").asString()).isEqualTo("new-cert");
        assertThat(merged.has("version")).isFalse();
    }

    @Test
    void merge_missingCertificateName_returnsCurrent() throws Exception {
        JsonNode current = objectMapper.readTree("{\"certificateName\":\"old\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"foo\":\"bar\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged).isSameAs(current);
    }
}
