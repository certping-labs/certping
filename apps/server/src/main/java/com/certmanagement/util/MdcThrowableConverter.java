// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import ch.qos.logback.classic.pattern.ThrowableProxyConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;

import java.util.Map;

/**
 * Logback throwable converter that prefixes <em>every</em> line of a stack trace with the same
 * {@code [req=... corr=... msg=... org=...]} that decorates the log event header.
 *
 * <p>Default {@code %ex} / {@code %xEx} converters print the header line with MDC, then dump the
 * stack frames plain underneath, breaking grep-by-id for exception causes. This converter rebuilds
 * the standard throwable rendering and inserts the MDC prefix on every line.
 *
 * <p>Registered as {@code %mdcEx} via {@code logback-spring.xml}:
 * <pre>{@code
 *   <conversionRule conversionWord="mdcEx"
 *                   converterClass="com.certmanagement.util.MdcThrowableConverter"/>
 *   <pattern>%d ... %msg%n%mdcEx</pattern>
 * }</pre>
 *
 * <p>The MDC snapshot is taken from the {@link ILoggingEvent} (which captures MDC at log time on
 * the originating thread), not from the current thread — important when the appender flushes
 * asynchronously.
 */
public class MdcThrowableConverter extends ThrowableProxyConverter {

    private static final String[] MDC_KEYS = {"requestId", "correlationId", "messageId", "organizationId"};

    @Override
    public String convert(ILoggingEvent event) {
        IThrowableProxy tp = event.getThrowableProxy();
        if (tp == null) {
            return "";
        }
        String rendered = super.convert(event);
        if (rendered == null || rendered.isEmpty()) {
            return rendered;
        }
        String prefix = buildPrefix(event.getMDCPropertyMap());
        // Insert the prefix at the start of every line. Logback's default trailing newline
        // produces an empty last segment when we split — preserve it untouched.
        String[] lines = rendered.split("\n", -1);
        StringBuilder sb = new StringBuilder(rendered.length() + lines.length * prefix.length());
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                sb.append('\n');
            }
            if (!lines[i].isEmpty()) {
                sb.append(prefix).append(lines[i]);
            }
        }
        return sb.toString();
    }

    private static String buildPrefix(Map<String, String> mdc) {
        if (mdc == null) mdc = Map.of();
        return "[req=" + valueOf(mdc, MDC_KEYS[0])
                + " corr=" + valueOf(mdc, MDC_KEYS[1])
                + " msg=" + valueOf(mdc, MDC_KEYS[2])
                + " org=" + valueOf(mdc, MDC_KEYS[3])
                + "] ";
    }

    private static String valueOf(Map<String, String> mdc, String key) {
        String v = mdc.get(key);
        return v == null ? "" : v;
    }
}
