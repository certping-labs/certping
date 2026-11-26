// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AwsArnResultMergerTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void merge_withArn_overwritesExistingArn() throws Exception {
        AwsArnResultMerger merger = new AwsArnResultMerger(objectMapper);
        JsonNode current = objectMapper.readTree("{\"arn\":\"old\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"arn\":\"new\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged.get("arn").asString()).isEqualTo("new");
    }

    @Test
    void merge_withoutArn_returnsCurrent() throws Exception {
        AwsArnResultMerger merger = new AwsArnResultMerger(objectMapper);
        JsonNode current = objectMapper.readTree("{\"arn\":\"old\"}");
        JsonNode fromAgent = objectMapper.readTree("{\"foo\":\"bar\"}");

        JsonNode merged = merger.merge(current, fromAgent);

        assertThat(merged).isSameAs(current);
    }

    @Test
    void merge_withNullCurrent_createsNewObject() throws Exception {
        AwsArnResultMerger merger = new AwsArnResultMerger(objectMapper);
        JsonNode fromAgent = objectMapper.readTree("{\"arn\":\"new-arn\"}");

        JsonNode merged = merger.merge(null, fromAgent);

        assertThat(merged.get("arn").asString()).isEqualTo("new-arn");
    }
}
