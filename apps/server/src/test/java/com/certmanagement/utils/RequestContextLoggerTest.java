// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.utils;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/** Unit tests for {@link RequestContextLogger} and its prefixing delegate. */
class RequestContextLoggerTest {

    @Test
    void getLoggerByClassReturnsWrapper() {
        Logger logger = RequestContextLogger.getLogger(RequestContextLoggerTest.class,
                "req-1", "corr-1", "idem-1");
        assertThat(logger).isNotNull();
        assertThat(logger.getName()).isEqualTo(RequestContextLoggerTest.class.getName());
    }

    @Test
    void infoPrependsRequestAndCorrelationAndIdempotencyPrefix() {
        Logger delegate = mock(Logger.class);
        Logger wrapper = RequestContextLogger.getLogger(delegate, "req-1", "corr-1", "idem-1");

        wrapper.info("hello {}", "world");

        ArgumentCaptor<String> fmt = ArgumentCaptor.forClass(String.class);
        verify(delegate).info(fmt.capture(), eq("world"));
        assertThat(fmt.getValue())
                .startsWith("[reqId=req-1|corrId=corr-1|idemKey=idem-1] ")
                .endsWith("hello {}");
    }

    @Test
    void unknownValuesUsedWhenNullAndIdemKeyOmittedWhenNoneOrNull() {
        Logger delegate = mock(Logger.class);
        Logger wrapper = RequestContextLogger.getLogger(delegate, null, null, "none");

        wrapper.warn("careful");

        ArgumentCaptor<String> msg = ArgumentCaptor.forClass(String.class);
        verify(delegate).warn(msg.capture());
        assertThat(msg.getValue())
                .isEqualTo("[reqId=unknown|corrId=unknown] careful")
                .doesNotContain("idemKey");
    }

    @Test
    void delegatesEnabledChecksAndAllLevels() {
        Logger delegate = mock(Logger.class);
        when(delegate.isDebugEnabled()).thenReturn(true);
        when(delegate.isErrorEnabled()).thenReturn(true);
        Logger wrapper = RequestContextLogger.getLogger(delegate, "r", "c", null);

        assertThat(wrapper.isDebugEnabled()).isTrue();
        assertThat(wrapper.isErrorEnabled()).isTrue();

        wrapper.debug("d");
        wrapper.error("e", new RuntimeException("boom"));
        wrapper.trace("t {} {}", 1, 2);

        verify(delegate).debug(startsWith("[reqId=r|corrId=c] d"));
        verify(delegate).error(startsWith("[reqId=r|corrId=c] e"), any(Throwable.class));
        verify(delegate).trace(startsWith("[reqId=r|corrId=c] t"), eq(1), eq(2));
    }

    @Test
    void markerVariantsArePrefixedToo() {
        Logger delegate = mock(Logger.class);
        Marker marker = MarkerFactory.getMarker("SECURITY");
        Logger wrapper = RequestContextLogger.getLogger(delegate, "r", "c", null);

        wrapper.info(marker, "with marker");

        verify(delegate).info(eq(marker), startsWith("[reqId=r|corrId=c] with marker"));
    }
}
