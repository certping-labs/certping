// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Exhaustive overload coverage for the prefixing {@code RequestContextAwareLogger}
 * — exercises every level (trace/debug/info/warn/error) across the plain,
 * 1-arg, 2-arg, varargs, throwable, and Marker overloads, plus the enabled
 * checks. Complements {@link RequestContextLoggerTest}.
 */
class RequestContextLoggerMoreTest {

    private Logger delegate;
    private Logger wrapper;
    private final Marker marker = MarkerFactory.getMarker("SEC");
    private static final String P = "[reqId=r|corrId=c] ";

    @BeforeEach
    void setUp() {
        delegate = mock(Logger.class);
        when(delegate.getName()).thenReturn("the.delegate");
        wrapper = RequestContextLogger.getLogger(delegate, "r", "c", null);
    }

    @Test
    void getName_delegates() {
        assertThat(wrapper.getName()).isEqualTo("the.delegate");
    }

    // ── TRACE ──────────────────────────────────────────────────────────
    @Test
    void traceOverloads() {
        when(delegate.isTraceEnabled()).thenReturn(true);
        when(delegate.isTraceEnabled(marker)).thenReturn(true);
        assertThat(wrapper.isTraceEnabled()).isTrue();
        assertThat(wrapper.isTraceEnabled(marker)).isTrue();

        wrapper.trace("m");
        wrapper.trace("f {}", "a");
        wrapper.trace("f {} {}", "a", "b");
        wrapper.trace("f {} {} {}", "a", "b", "c");
        wrapper.trace("m", new RuntimeException("x"));
        wrapper.trace(marker, "m");
        wrapper.trace(marker, "f {}", "a");
        wrapper.trace(marker, "f {} {}", "a", "b");
        wrapper.trace(marker, "f {} {} {}", "a", "b", "c");
        wrapper.trace(marker, "m", new RuntimeException("x"));

        verify(delegate).trace(startsWith(P));
        verify(delegate).trace(startsWith(P), eq("a"));
        verify(delegate).trace(startsWith(P), eq("a"), eq("b"));
        verify(delegate).trace(startsWith(P), any(Object[].class));
        verify(delegate).trace(startsWith(P), any(Throwable.class));
        verify(delegate).trace(eq(marker), startsWith(P));
        verify(delegate).trace(eq(marker), startsWith(P), eq("a"));
        verify(delegate).trace(eq(marker), startsWith(P), eq("a"), eq("b"));
        verify(delegate).trace(eq(marker), startsWith(P), any(Object[].class));
        verify(delegate).trace(eq(marker), startsWith(P), any(Throwable.class));
    }

    // ── DEBUG ──────────────────────────────────────────────────────────
    @Test
    void debugOverloads() {
        when(delegate.isDebugEnabled()).thenReturn(true);
        when(delegate.isDebugEnabled(marker)).thenReturn(true);
        assertThat(wrapper.isDebugEnabled()).isTrue();
        assertThat(wrapper.isDebugEnabled(marker)).isTrue();

        wrapper.debug("m");
        wrapper.debug("f {}", "a");
        wrapper.debug("f {} {}", "a", "b");
        wrapper.debug("f {} {} {}", "a", "b", "c");
        wrapper.debug("m", new RuntimeException("x"));
        wrapper.debug(marker, "m");
        wrapper.debug(marker, "f {}", "a");
        wrapper.debug(marker, "f {} {}", "a", "b");
        wrapper.debug(marker, "f {} {} {}", "a", "b", "c");
        wrapper.debug(marker, "m", new RuntimeException("x"));

        verify(delegate).debug(startsWith(P));
        verify(delegate).debug(startsWith(P), eq("a"));
        verify(delegate).debug(startsWith(P), eq("a"), eq("b"));
        verify(delegate).debug(startsWith(P), any(Object[].class));
        verify(delegate).debug(startsWith(P), any(Throwable.class));
        verify(delegate).debug(eq(marker), startsWith(P));
        verify(delegate).debug(eq(marker), startsWith(P), eq("a"));
        verify(delegate).debug(eq(marker), startsWith(P), eq("a"), eq("b"));
        verify(delegate).debug(eq(marker), startsWith(P), any(Object[].class));
        verify(delegate).debug(eq(marker), startsWith(P), any(Throwable.class));
    }

    // ── INFO ───────────────────────────────────────────────────────────
    @Test
    void infoOverloads() {
        when(delegate.isInfoEnabled()).thenReturn(true);
        when(delegate.isInfoEnabled(marker)).thenReturn(true);
        assertThat(wrapper.isInfoEnabled()).isTrue();
        assertThat(wrapper.isInfoEnabled(marker)).isTrue();

        wrapper.info("m");
        wrapper.info("f {}", "a");
        wrapper.info("f {} {}", "a", "b");
        wrapper.info("f {} {} {}", "a", "b", "c");
        wrapper.info("m", new RuntimeException("x"));
        wrapper.info(marker, "m");
        wrapper.info(marker, "f {}", "a");
        wrapper.info(marker, "f {} {}", "a", "b");
        wrapper.info(marker, "f {} {} {}", "a", "b", "c");
        wrapper.info(marker, "m", new RuntimeException("x"));

        verify(delegate).info(startsWith(P));
        verify(delegate).info(startsWith(P), eq("a"));
        verify(delegate).info(startsWith(P), eq("a"), eq("b"));
        verify(delegate).info(startsWith(P), any(Object[].class));
        verify(delegate).info(startsWith(P), any(Throwable.class));
        verify(delegate).info(eq(marker), startsWith(P));
        verify(delegate).info(eq(marker), startsWith(P), eq("a"));
        verify(delegate).info(eq(marker), startsWith(P), eq("a"), eq("b"));
        verify(delegate).info(eq(marker), startsWith(P), any(Object[].class));
        verify(delegate).info(eq(marker), startsWith(P), any(Throwable.class));
    }

    // ── WARN ───────────────────────────────────────────────────────────
    @Test
    void warnOverloads() {
        when(delegate.isWarnEnabled()).thenReturn(true);
        when(delegate.isWarnEnabled(marker)).thenReturn(true);
        assertThat(wrapper.isWarnEnabled()).isTrue();
        assertThat(wrapper.isWarnEnabled(marker)).isTrue();

        wrapper.warn("m");
        wrapper.warn("f {}", "a");
        wrapper.warn("f {} {}", "a", "b");
        wrapper.warn("f {} {} {}", "a", "b", "c");
        wrapper.warn("m", new RuntimeException("x"));
        wrapper.warn(marker, "m");
        wrapper.warn(marker, "f {}", "a");
        wrapper.warn(marker, "f {} {}", "a", "b");
        wrapper.warn(marker, "f {} {} {}", "a", "b", "c");
        wrapper.warn(marker, "m", new RuntimeException("x"));

        verify(delegate).warn(startsWith(P));
        verify(delegate).warn(startsWith(P), eq("a"));
        verify(delegate).warn(startsWith(P), eq("a"), eq("b"));
        verify(delegate).warn(startsWith(P), any(Object[].class));
        verify(delegate).warn(startsWith(P), any(Throwable.class));
        verify(delegate).warn(eq(marker), startsWith(P));
        verify(delegate).warn(eq(marker), startsWith(P), eq("a"));
        verify(delegate).warn(eq(marker), startsWith(P), eq("a"), eq("b"));
        verify(delegate).warn(eq(marker), startsWith(P), any(Object[].class));
        verify(delegate).warn(eq(marker), startsWith(P), any(Throwable.class));
    }

    // ── ERROR ──────────────────────────────────────────────────────────
    @Test
    void errorOverloads() {
        when(delegate.isErrorEnabled()).thenReturn(true);
        when(delegate.isErrorEnabled(marker)).thenReturn(true);
        assertThat(wrapper.isErrorEnabled()).isTrue();
        assertThat(wrapper.isErrorEnabled(marker)).isTrue();

        wrapper.error("m");
        wrapper.error("f {}", "a");
        wrapper.error("f {} {}", "a", "b");
        wrapper.error("f {} {} {}", "a", "b", "c");
        wrapper.error("m", new RuntimeException("x"));
        wrapper.error(marker, "m");
        wrapper.error(marker, "f {}", "a");
        wrapper.error(marker, "f {} {}", "a", "b");
        wrapper.error(marker, "f {} {} {}", "a", "b", "c");
        wrapper.error(marker, "m", new RuntimeException("x"));

        verify(delegate).error(startsWith(P));
        verify(delegate).error(startsWith(P), eq("a"));
        verify(delegate).error(startsWith(P), eq("a"), eq("b"));
        verify(delegate).error(startsWith(P), any(Object[].class));
        verify(delegate).error(startsWith(P), any(Throwable.class));
        verify(delegate).error(eq(marker), startsWith(P));
        verify(delegate).error(eq(marker), startsWith(P), eq("a"));
        verify(delegate).error(eq(marker), startsWith(P), eq("a"), eq("b"));
        verify(delegate).error(eq(marker), startsWith(P), any(Object[].class));
        verify(delegate).error(eq(marker), startsWith(P), any(Throwable.class));
    }

    @Test
    void getLoggerByClass_returnsFunctionalWrapper() {
        Logger byClass = RequestContextLogger.getLogger(getClass(), "rq", "co", "ik");
        assertThat(byClass.getName()).isEqualTo(getClass().getName());
    }
}
