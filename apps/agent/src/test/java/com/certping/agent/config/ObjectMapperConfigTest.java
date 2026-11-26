// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.config;

import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(ObjectMapperConfig.class)
class ObjectMapperConfigTest {

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void objectMapper_serializesInstantAsIsoString() throws Exception {
        Instant t = Instant.parse("2024-01-15T12:00:00Z");
        String json = objectMapper.writeValueAsString(t);
        assertThat(json).contains("2024-01-15");
        assertThat(json).doesNotContainPattern("\\d{13}");
    }

    @Test
    void objectMapper_ignoresUnknownProperties() throws Exception {
        String json = "{\"known\":1,\"extra\":2}";
        record Holder(int known) {}
        Holder h = objectMapper.readValue(json, Holder.class);
        assertThat(h.known()).isEqualTo(1);
    }
}
