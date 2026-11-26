// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DiscoveryScopeKeyFactoryTest {

    private final DiscoveryScopeKeyFactory factory = new DiscoveryScopeKeyFactory(JsonMapper.builderWithJackson2Defaults().build());

    @Test
    void create_isStableAcrossJsonObjectFieldOrder() {
        String first = factory.create(42L, "AWS_ACM", "cred-1",
                "{\"region\":\"us-east-1\",\"authMode\":\"STATIC_KEYS\"}");
        String second = factory.create(42L, "AWS_ACM", "cred-1",
                "{\"authMode\":\"STATIC_KEYS\",\"region\":\"us-east-1\"}");

        assertThat(first).isEqualTo(second).hasSize(64);
    }

    @Test
    void create_separatesCredentialsAndScopes() {
        String baseline = factory.create(42L, "AWS_ACM", "cred-1", "{\"region\":\"us-east-1\"}");

        assertThat(factory.create(42L, "AWS_ACM", "cred-2", "{\"region\":\"us-east-1\"}"))
                .isNotEqualTo(baseline);
        assertThat(factory.create(42L, "AWS_ACM", "cred-1", "{\"region\":\"eu-west-1\"}"))
                .isNotEqualTo(baseline);
    }

    @Test
    void create_rejectsMalformedScope() {
        assertThatThrownBy(() -> factory.create(42L, "AWS_ACM", "cred-1", "{bad-json}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("valid JSON");
    }
}
