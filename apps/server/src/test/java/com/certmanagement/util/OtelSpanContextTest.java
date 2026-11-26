// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link OtelSpanContext}. With no OpenTelemetry agent active, {@code Span.current()}
 * returns a no-op span, so the enrich* methods must execute without throwing. We focus assertions on
 * the pure {@link OtelSpanContext#fieldAsString} helper and verify the enrich paths are exception-free.
 */
class OtelSpanContextTest {

    @Test
    void fieldAsStringReturnsStringValue() {
        Map<String, Object> fields = new HashMap<>();
        fields.put("count", 42);
        fields.put("name", "acme");
        assertThat(OtelSpanContext.fieldAsString(fields, "count")).isEqualTo("42");
        assertThat(OtelSpanContext.fieldAsString(fields, "name")).isEqualTo("acme");
    }

    @Test
    void fieldAsStringReturnsNullForMissingOrNullInputs() {
        assertThat(OtelSpanContext.fieldAsString(null, "k")).isNull();
        assertThat(OtelSpanContext.fieldAsString(Map.of("a", "b"), null)).isNull();
        assertThat(OtelSpanContext.fieldAsString(Map.of("a", "b"), "missing")).isNull();
    }

    @Test
    void fieldAsStringHandlesNullValue() {
        Map<String, Object> fields = new HashMap<>();
        fields.put("k", null);
        assertThat(OtelSpanContext.fieldAsString(fields, "k")).isNull();
    }

    @Test
    void enrichMethodsDoNotThrowWithNoopSpan() {
        assertThatCode(() -> {
            OtelSpanContext.enrichHttp("req", "corr", "org", "user");
            OtelSpanContext.enrichHttp(null, "", "unknown", null);
            OtelSpanContext.enrichAgentMessage("req", "corr", "org", "xref", "type", "mid");
            OtelSpanContext.enrichAgentPublish("req", "corr", "org", "xref", "type", "mid");
            OtelSpanContext.enrichScheduledTick("req-sched");
            OtelSpanContext.enrichNotificationPublish("req", "corr", "org", "xref", "action", "ntype", "mid");
            OtelSpanContext.enrichNotificationConsume("req", "corr", "org", "xref", "action", "ntype", "mid", "user");
        }).doesNotThrowAnyException();
    }
}
