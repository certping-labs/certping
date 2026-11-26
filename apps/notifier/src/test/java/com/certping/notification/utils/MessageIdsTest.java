// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.utils;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MessageIdsTest {

    private static final String TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    @Test
    void readsTheThreeApplicationProperties() {
        MessageIds ids = MessageIds.from(Map.of("correlationId", "corr-http-1", "requestId", "req-http-1",
                "traceparent", TRACEPARENT));

        assertThat(ids).isEqualTo(new MessageIds("corr-http-1", "req-http-1", TRACEPARENT));
    }

    @Test
    void aMissingOrInvalidPropertyIsNull() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("correlationId", "corr 1\nlevel=ERROR forged");
        properties.put("requestId", 42);
        properties.put("traceparent", "not-a-traceparent");

        assertThat(MessageIds.from(properties)).isEqualTo(new MessageIds(null, null, null));
        assertThat(MessageIds.from(null)).isEqualTo(new MessageIds(null, null, null));
    }

    @Test
    void anIdIsAtMost128CharactersOfTheAllowedSet() {
        assertThat(MessageIds.valid("domain-renewal-skipped:7:2027-03-01")).isEqualTo("domain-renewal-skipped:7:2027-03-01");
        assertThat(MessageIds.valid("a".repeat(128))).hasSize(128);
        assertThat(MessageIds.valid("a".repeat(129))).isNull();
        assertThat(MessageIds.valid("ada@example.com")).isNull();
        assertThat(MessageIds.valid("")).isNull();
        assertThat(MessageIds.valid(null)).isNull();
    }

    @Test
    void aKeyIsLoggedAsItselfOnlyWhenValidElseAsADigest() {
        assertThat(MessageIds.loggable("cert-issued-email:5")).isEqualTo("cert-issued-email:5");
        String forged = MessageIds.loggable("key 1\nlevel=ERROR forged");
        assertThat(forged).startsWith("sha256:").doesNotContain("forged");
        assertThat(MessageIds.valid(forged)).isEqualTo(forged);
        assertThat(MessageIds.loggable("key 1\nlevel=ERROR forged")).isEqualTo(forged);
        assertThat(MessageIds.loggable(" ")).isNull();
        assertThat(MessageIds.loggable(null)).isNull();
    }
}
