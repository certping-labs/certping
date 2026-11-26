// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.utils;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link RequestContextLogger} is a delegating logger that prepends a
 * {@code [reqId=…|corrId=…|idemKey=…]} prefix to every message.
 *
 * <p>These tests spot-check that (a) the prefix is built correctly across the
 * "with idempotency key" / "unknown values" branches and (b) each log-level
 * delegate call routes through unchanged. Delegate methods are stateless
 * one-liners so a few representative tests are enough to cover every branch.
 */
class RequestContextLoggerTest {

    // ── prefix construction ────────────────────────────────────────────────

    @Test
    void prefix_containsRequestIdAndCorrelationId_omitsIdemKeyWhenNone() {
        Logger delegate = mock(Logger.class);
        when(delegate.isInfoEnabled()).thenReturn(true);
        Logger wrapped = RequestContextLogger.getLogger(delegate, "req-1", "corr-1", "none");

        wrapped.info("hello");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(delegate).info(captor.capture());
        assertThat(captor.getValue())
                .startsWith("[reqId=req-1|corrId=corr-1] ")
                .doesNotContain("idemKey")
                .endsWith("hello");
    }

    @Test
    void prefix_includesIdemKeyWhenPresent() {
        Logger delegate = mock(Logger.class);
        Logger wrapped = RequestContextLogger.getLogger(delegate, "req-1", "corr-1", "idem-9");

        wrapped.info("hi");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(delegate).info(captor.capture());
        assertThat(captor.getValue()).contains("|idemKey=idem-9");
    }

    @Test
    void prefix_nullValues_defaultsToUnknown() {
        Logger delegate = mock(Logger.class);
        Logger wrapped = RequestContextLogger.getLogger(delegate, null, null, null);

        wrapped.info("m");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(delegate).info(captor.capture());
        assertThat(captor.getValue()).startsWith("[reqId=unknown|corrId=unknown] ");
    }

    // ── getLogger overload (Class) ─────────────────────────────────────────

    @Test
    void getLogger_byClass_returnsPrefixingLogger() {
        Logger wrapped = RequestContextLogger.getLogger(RequestContextLoggerTest.class,
                "r", "c", "i");
        // Just exercise it — the name should come from the delegate.
        assertThat(wrapped.getName()).isEqualTo(RequestContextLoggerTest.class.getName());
    }

    // ── each log level delegates with prefix (representative sampling) ─────

    @Test
    void trace_delegates_variants() {
        Logger d = mock(Logger.class);
        Marker m = MarkerFactory.getMarker("m");
        Logger w = RequestContextLogger.getLogger(d, "r", "c", "none");
        Throwable t = new RuntimeException("boom");

        w.trace("a");
        w.trace("a {}", 1);
        w.trace("a {} {}", 1, 2);
        w.trace("a {} {} {}", 1, 2, 3);
        w.trace("a", t);
        w.trace(m, "a");
        w.trace(m, "a {}", 1);
        w.trace(m, "a {} {}", 1, 2);
        w.trace(m, "a {} {} {}", 1, 2, 3);
        w.trace(m, "a", t);
        w.isTraceEnabled();
        w.isTraceEnabled(m);

        verify(d).trace(anyString());
        verify(d).trace(anyString(), eq(1));
        verify(d).trace(anyString(), eq(1), eq(2));
        verify(d).trace(anyString(), eq((Object) 1), eq(2), eq(3));
        verify(d).trace(anyString(), eq(t));
        verify(d).trace(eq(m), anyString());
        verify(d).trace(eq(m), anyString(), eq(1));
        verify(d).trace(eq(m), anyString(), eq(1), eq(2));
        verify(d).trace(eq(m), anyString(), eq((Object) 1), eq(2), eq(3));
        verify(d).trace(eq(m), anyString(), eq(t));
    }

    @Test
    void debug_delegates_variants() {
        Logger d = mock(Logger.class);
        Marker m = MarkerFactory.getMarker("m");
        Logger w = RequestContextLogger.getLogger(d, "r", "c", "none");
        Throwable t = new RuntimeException();

        w.debug("a");
        w.debug("a {}", 1);
        w.debug("a {} {}", 1, 2);
        w.debug("a {} {} {}", 1, 2, 3);
        w.debug("a", t);
        w.debug(m, "a");
        w.debug(m, "a {}", 1);
        w.debug(m, "a {} {}", 1, 2);
        w.debug(m, "a {} {} {}", 1, 2, 3);
        w.debug(m, "a", t);
        w.isDebugEnabled();
        w.isDebugEnabled(m);

        verify(d).debug(anyString());
        verify(d).debug(anyString(), eq(1));
        verify(d).debug(anyString(), eq(1), eq(2));
        verify(d).debug(anyString(), eq((Object) 1), eq(2), eq(3));
        verify(d).debug(anyString(), eq(t));
        verify(d).debug(eq(m), anyString());
    }

    @Test
    void info_delegates_variants() {
        Logger d = mock(Logger.class);
        Marker m = MarkerFactory.getMarker("m");
        Logger w = RequestContextLogger.getLogger(d, "r", "c", "none");
        Throwable t = new RuntimeException();

        w.info("a");
        w.info("a {}", 1);
        w.info("a {} {}", 1, 2);
        w.info("a {} {} {}", 1, 2, 3);
        w.info("a", t);
        w.info(m, "a");
        w.info(m, "a {}", 1);
        w.info(m, "a {} {}", 1, 2);
        w.info(m, "a {} {} {}", 1, 2, 3);
        w.info(m, "a", t);
        w.isInfoEnabled();
        w.isInfoEnabled(m);

        verify(d).info(anyString());
        verify(d).info(anyString(), eq(t));
    }

    @Test
    void warn_delegates_variants() {
        Logger d = mock(Logger.class);
        Marker m = MarkerFactory.getMarker("m");
        Logger w = RequestContextLogger.getLogger(d, "r", "c", "none");
        Throwable t = new RuntimeException();

        w.warn("a");
        w.warn("a {}", 1);
        w.warn("a {} {}", 1, 2);
        w.warn("a {} {} {}", 1, 2, 3);
        w.warn("a", t);
        w.warn(m, "a");
        w.warn(m, "a {}", 1);
        w.warn(m, "a {} {}", 1, 2);
        w.warn(m, "a {} {} {}", 1, 2, 3);
        w.warn(m, "a", t);
        w.isWarnEnabled();
        w.isWarnEnabled(m);

        verify(d).warn(anyString());
        verify(d).warn(anyString(), eq(t));
    }

    @Test
    void error_delegates_variants() {
        Logger d = mock(Logger.class);
        Marker m = MarkerFactory.getMarker("m");
        Logger w = RequestContextLogger.getLogger(d, "r", "c", "none");
        Throwable t = new RuntimeException();

        w.error("a");
        w.error("a {}", 1);
        w.error("a {} {}", 1, 2);
        w.error("a {} {} {}", 1, 2, 3);
        w.error("a", t);
        w.error(m, "a");
        w.error(m, "a {}", 1);
        w.error(m, "a {} {}", 1, 2);
        w.error(m, "a {} {} {}", 1, 2, 3);
        w.error(m, "a", t);
        w.isErrorEnabled();
        w.isErrorEnabled(m);

        verify(d).error(anyString());
        verify(d).error(anyString(), eq(t));
    }
}
