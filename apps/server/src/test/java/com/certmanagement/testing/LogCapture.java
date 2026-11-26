// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.testing;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/** Captures the events of a few loggers at DEBUG and puts their levels back on close. */
public final class LogCapture implements AutoCloseable {

    private final List<Logger> loggers = new ArrayList<>();
    private final List<Level> previousLevels = new ArrayList<>();
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    private LogCapture(Class<?>... sources) {
        appender.start();
        for (Class<?> source : sources) {
            Logger logger = (Logger) LoggerFactory.getLogger(source);
            loggers.add(logger);
            previousLevels.add(logger.getLevel());
            logger.setLevel(Level.DEBUG);
            logger.addAppender(appender);
        }
    }

    public static LogCapture of(Class<?>... sources) {
        return new LogCapture(sources);
    }

    public List<ILoggingEvent> events() {
        return List.copyOf(appender.list);
    }

    public List<String> messages() {
        return events().stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    /** What an INFO appender would print, including exception messages in the cause chain. */
    public List<String> infoOutput() {
        return events().stream()
                .filter(event -> event.getLevel().isGreaterOrEqual(Level.INFO))
                .map(LogCapture::render)
                .toList();
    }

    private static String render(ILoggingEvent event) {
        StringBuilder out = new StringBuilder(event.getFormattedMessage());
        for (IThrowableProxy t = event.getThrowableProxy(); t != null; t = t.getCause()) {
            out.append(" | ").append(t.getClassName()).append(": ").append(t.getMessage());
        }
        return out.toString();
    }

    @Override
    public void close() {
        for (int i = 0; i < loggers.size(); i++) {
            loggers.get(i).detachAppender(appender);
            loggers.get(i).setLevel(previousLevels.get(i));
        }
        appender.stop();
    }
}
