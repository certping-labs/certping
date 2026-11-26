// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link MdcThrowableConverter}. */
class MdcThrowableConverterTest {

    private MdcThrowableConverter converter;
    private LoggerContext context;

    @BeforeEach
    void setUp() {
        converter = new MdcThrowableConverter();
        context = (LoggerContext) LoggerFactory.getILoggerFactory();
        converter.setContext(context);
        converter.start();
    }

    private LoggingEvent eventWith(Throwable t, Map<String, String> mdc) {
        Logger logbackLogger = context.getLogger(MdcThrowableConverterTest.class);
        LoggingEvent event = new LoggingEvent(
                MdcThrowableConverterTest.class.getName(), logbackLogger,
                ch.qos.logback.classic.Level.ERROR, "boom", t, null);
        if (mdc != null) {
            event.setMDCPropertyMap(mdc);
        }
        return event;
    }

    @Test
    void returnsEmptyStringWhenNoThrowable() {
        LoggingEvent event = eventWith(null, Map.of("requestId", "r1"));
        assertThat(converter.convert(event)).isEmpty();
    }

    @Test
    void prefixesEveryStackLineWithMdcValues() {
        RuntimeException ex = new RuntimeException("kaboom");
        LoggingEvent event = eventWith(ex, Map.of(
                "requestId", "req-1",
                "correlationId", "corr-2",
                "messageId", "msg-3",
                "organizationId", "org-4"));

        String rendered = converter.convert(event);

        assertThat(rendered)
                .contains("[req=req-1 corr=corr-2 msg=msg-3 org=org-4]")
                .contains("kaboom");
        // Every non-empty line carries the prefix.
        for (String line : rendered.split("\n", -1)) {
            if (!line.isEmpty()) {
                assertThat(line).startsWith("[req=req-1");
            }
        }
    }

    @Test
    void emptyMdcRendersBlankIdSlots() {
        RuntimeException ex = new RuntimeException("x");
        LoggingEvent event = eventWith(ex, Map.of());
        String rendered = converter.convert(event);
        assertThat(rendered).contains("[req= corr= msg= org=]");
    }
}
