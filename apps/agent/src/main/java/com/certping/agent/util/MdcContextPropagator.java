// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.util;

import org.slf4j.MDC;

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * MDC propagation helpers for code that hands work to other threads.
 *
 * <p>SLF4J's MDC is backed by a {@link ThreadLocal}, so a task submitted to an executor or
 * launched via {@code CompletableFuture.runAsync(...)} runs with an <em>empty</em> MDC unless we
 * copy the caller's context map onto the worker thread. Without this propagation, log lines
 * emitted from background threads lose their {@code [req=... corr=... msg=...]} prefix and you
 * cannot grep a request end-to-end.
 *
 * <p>Usage:
 * <pre>{@code
 *   CompletableFuture.runAsync(MdcContextPropagator.wrap(() -> doWork(item)));
 *   executor.submit(MdcContextPropagator.wrap(() -> compute(x)));
 * }</pre>
 *
 * <p>The wrapper snapshots the caller's MDC at decoration time, installs it on the worker thread
 * for the duration of the task, then restores whatever was there before (typically empty). This
 * keeps pooled threads from leaking IDs between tasks.
 */
public final class MdcContextPropagator {

    private MdcContextPropagator() {
        // utility class
    }

    /** Snapshot caller MDC, install it on the worker thread for the runnable, restore after. */
    public static Runnable wrap(Runnable delegate) {
        Map<String, String> captured = MDC.getCopyOfContextMap();
        return () -> {
            Map<String, String> previous = MDC.getCopyOfContextMap();
            installContext(captured);
            try {
                delegate.run();
            } finally {
                installContext(previous);
            }
        };
    }

    /** Same as {@link #wrap(Runnable)} but for value-returning tasks. */
    public static <T> Callable<T> wrap(Callable<T> delegate) {
        Map<String, String> captured = MDC.getCopyOfContextMap();
        return () -> {
            Map<String, String> previous = MDC.getCopyOfContextMap();
            installContext(captured);
            try {
                return delegate.call();
            } finally {
                installContext(previous);
            }
        };
    }

    /** Same as {@link #wrap(Runnable)} but for {@link Supplier} (used by CompletableFuture). */
    public static <T> Supplier<T> wrap(Supplier<T> delegate) {
        Map<String, String> captured = MDC.getCopyOfContextMap();
        return () -> {
            Map<String, String> previous = MDC.getCopyOfContextMap();
            installContext(captured);
            try {
                return delegate.get();
            } finally {
                installContext(previous);
            }
        };
    }

    private static void installContext(Map<String, String> ctx) {
        MDC.clear();
        if (ctx != null) {
            MDC.setContextMap(ctx);
        }
    }
}
