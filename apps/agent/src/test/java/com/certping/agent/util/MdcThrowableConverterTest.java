// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.util;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MdcThrowableConverterTest {

    private final MdcThrowableConverter converter = new MdcThrowableConverter();

    @Test
    void convert_noThrowable_returnsEmpty() {
        LoggingEvent event = baseEvent();
        // No throwable proxy → empty render so we don't print an unrelated blank prefix line.
        assertThat(converter.convert(event)).isEmpty();
    }

    @Test
    void convert_prefixesEveryNonEmptyLine() {
        // Real Throwable so logback can render a real stack trace (the converter delegates to
        // its superclass for the rendering, then injects the MDC prefix).
        Throwable cause = new IllegalStateException("boom");
        LoggingEvent event = baseEvent();
        event.setThrowableProxy(new ThrowableProxy(cause));
        event.setMDCPropertyMap(Map.of(
                "requestId", "req-X",
                "correlationId", "corr-Y",
                "messageId", "msg-Z",
                "organizationId", "org-42"));
        // ThrowableProxyConverter needs to be started before convert() will produce output
        converter.start();

        String rendered = converter.convert(event);

        assertThat(rendered).isNotBlank();
        String expectedPrefix = "[req=req-X corr=corr-Y msg=msg-Z org=org-42] ";
        // Every non-empty line should start with the MDC prefix — split on newline and assert.
        String[] lines = rendered.split("\n", -1);
        for (String line : lines) {
            if (!line.isEmpty()) {
                assertThat(line).startsWith(expectedPrefix);
            }
        }
        // Sanity: the rendered text actually contains the exception class + message.
        assertThat(rendered).contains("IllegalStateException").contains("boom");
    }

    @Test
    void convert_emptyMdc_emitsBlankIdsButStillPrefixes() {
        Throwable cause = new RuntimeException("oops");
        LoggingEvent event = baseEvent();
        event.setThrowableProxy(new ThrowableProxy(cause));
        event.setMDCPropertyMap(Map.of());
        converter.start();

        String rendered = converter.convert(event);
        assertThat(rendered).contains("[req= corr= msg= org=] ");
    }

    private LoggingEvent baseEvent() {
        LoggerContext ctx = new LoggerContext();
        Logger logger = ctx.getLogger("test");
        LoggingEvent event = new LoggingEvent();
        event.setLoggerName("test");
        event.setLevel(Level.ERROR);
        event.setLoggerContextRemoteView(ctx.getLoggerContextRemoteView());
        return event;
    }
}
