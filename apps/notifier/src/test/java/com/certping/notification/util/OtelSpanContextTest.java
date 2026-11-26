// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.util;

import io.opentelemetry.api.trace.Span;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class OtelSpanContextTest {

    @Test
    void enrichHttp_setsBothAttributes() {
        Span span = mock(Span.class);
        try (MockedStatic<Span> spanStatic = mockStatic(Span.class)) {
            spanStatic.when(Span::current).thenReturn(span);
            OtelSpanContext.enrichHttp("req-1", "corr-1");
        }
        verify(span).setAttribute("request.id", "req-1");
        verify(span).setAttribute("correlation.id", "corr-1");
    }

    @Test
    void enrichHttp_nullAndBlankValues_skipped() {
        Span span = mock(Span.class);
        try (MockedStatic<Span> spanStatic = mockStatic(Span.class)) {
            spanStatic.when(Span::current).thenReturn(span);
            OtelSpanContext.enrichHttp(null, "");
        }
        verify(span, never()).setAttribute(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void enrichHttp_unknownValue_treatedAsAbsent() {
        Span span = mock(Span.class);
        try (MockedStatic<Span> spanStatic = mockStatic(Span.class)) {
            spanStatic.when(Span::current).thenReturn(span);
            OtelSpanContext.enrichHttp("unknown", "unknown");
        }
        verify(span, never()).setAttribute(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void enrichInboundBatch_setsAllPresentAttributes() {
        Span span = mock(Span.class);
        try (MockedStatic<Span> spanStatic = mockStatic(Span.class)) {
            spanStatic.when(Span::current).thenReturn(span);
            OtelSpanContext.enrichInboundBatch("req-1", "corr-1", "msg-1");
        }
        verify(span).setAttribute("request.id", "req-1");
        verify(span).setAttribute("correlation.id", "corr-1");
        verify(span).setAttribute("messaging.message.id", "msg-1");
    }

    @Test
    void enrichNotificationConsume_allFieldsPresent_setsAll() {
        Span span = mock(Span.class);
        try (MockedStatic<Span> spanStatic = mockStatic(Span.class)) {
            spanStatic.when(Span::current).thenReturn(span);
            OtelSpanContext.enrichNotificationConsume(
                    "req", "corr", "org1", "cert-42",
                    "CERT_ISSUANCE_SUCCESS", "ACCOUNT_EVENT", "msg-99", "user-7");
        }
        verify(span).setAttribute("request.id", "req");
        verify(span).setAttribute("correlation.id", "corr");
        verify(span).setAttribute("organization.id", "org1");
        verify(span).setAttribute("certificate.xref", "cert-42");
        verify(span).setAttribute("message.type", "CERT_ISSUANCE_SUCCESS");
        verify(span).setAttribute("notification.type", "ACCOUNT_EVENT");
        verify(span).setAttribute("messaging.message.id", "msg-99");
        verify(span).setAttribute("user.id", "user-7");
    }

    @Test
    void enrichNotificationConsume_mixedNullValues_setsOnlyNonNull() {
        Span span = mock(Span.class);
        try (MockedStatic<Span> spanStatic = mockStatic(Span.class)) {
            spanStatic.when(Span::current).thenReturn(span);
            OtelSpanContext.enrichNotificationConsume(
                    "req", null, "org1", null,
                    null, null, "msg-99", null);
        }
        verify(span).setAttribute("request.id", "req");
        verify(span).setAttribute("organization.id", "org1");
        verify(span).setAttribute("messaging.message.id", "msg-99");
        verify(span, never()).setAttribute(
                org.mockito.ArgumentMatchers.eq("correlation.id"),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void fieldAsString_nullMap_returnsNull() {
        assertThat(OtelSpanContext.fieldAsString(null, "k")).isNull();
    }

    @Test
    void fieldAsString_nullKey_returnsNull() {
        assertThat(OtelSpanContext.fieldAsString(Map.of("k", "v"), null)).isNull();
    }

    @Test
    void fieldAsString_missingKey_returnsNull() {
        assertThat(OtelSpanContext.fieldAsString(Map.of("other", "v"), "k")).isNull();
    }

    @Test
    void fieldAsString_nullValue_returnsNull() {
        Map<String, Object> m = new HashMap<>();
        m.put("k", null);
        assertThat(OtelSpanContext.fieldAsString(m, "k")).isNull();
    }

    @Test
    void fieldAsString_stringValue_returnedAsIs() {
        assertThat(OtelSpanContext.fieldAsString(Map.of("k", "value"), "k")).isEqualTo("value");
    }

    @Test
    void fieldAsString_nonStringValue_toStringed() {
        assertThat(OtelSpanContext.fieldAsString(Map.of("k", 42), "k")).isEqualTo("42");
    }
}
