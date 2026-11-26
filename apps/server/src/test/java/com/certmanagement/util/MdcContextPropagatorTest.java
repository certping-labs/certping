// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import com.certmanagement.interceptor.RequestContextInterceptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link MdcContextPropagator}. */
class MdcContextPropagatorTest {

    @BeforeEach
    @AfterEach
    void clear() {
        RequestContextInterceptor.clearContext();
        MDC.clear();
    }

    @Test
    void aWrappedTaskSeesTheRequestIdsButNotTheClientAddress() throws Exception {
        RequestContextInterceptor.setCurrentRequestId("req-w");
        RequestContextInterceptor.setCurrentCorrelationId("corr-w");
        RequestContextInterceptor.setCurrentIdempotencyKey("idem-w");
        RequestContextInterceptor.setCurrentClientIp("198.51.100.7");
        AtomicReference<String> seen = new AtomicReference<>();
        Runnable wrapped = MdcContextPropagator.wrap(() -> seen.set(RequestContextInterceptor.getCurrentRequestId()
                + "|" + RequestContextInterceptor.getCurrentCorrelationId()
                + "|" + RequestContextInterceptor.getCurrentIdempotencyKey()
                + "|" + RequestContextInterceptor.getCurrentClientIp()));

        Thread t = new Thread(wrapped);
        t.start();
        t.join();

        assertThat(seen.get()).isEqualTo("req-w|corr-w|idem-w|null");
    }

    @Test
    void wrapRunnableInstallsCapturedContextAndRestores() throws Exception {
        MDC.put("requestId", "req-1");
        AtomicReference<String> seen = new AtomicReference<>();

        Runnable wrapped = MdcContextPropagator.wrap(() -> seen.set(MDC.get("requestId")));

        // Simulate running on a worker thread with different MDC.
        Thread t = new Thread(() -> {
            MDC.put("requestId", "worker-pre");
            wrapped.run();
            // After the wrapped task, the worker's previous context is restored.
            assertThat(MDC.get("requestId")).isEqualTo("worker-pre");
        });
        t.start();
        t.join();

        assertThat(seen.get()).isEqualTo("req-1");
    }

    @Test
    void wrapCallableReturnsValueWithCapturedContext() throws Exception {
        MDC.put("correlationId", "corr-9");
        Callable<String> wrapped = MdcContextPropagator.wrap(
                (Callable<String>) () -> MDC.get("correlationId"));
        assertThat(wrapped.call()).isEqualTo("corr-9");
    }

    @Test
    void wrapSupplierReturnsValueWithCapturedContext() {
        MDC.put("requestId", "req-supplier");
        Supplier<String> wrapped = MdcContextPropagator.wrap(
                (Supplier<String>) () -> MDC.get("requestId"));
        assertThat(wrapped.get()).isEqualTo("req-supplier");
    }

    @Test
    void wrapRunnableWithEmptyCallerContextClearsWorkerContext() throws Exception {
        // No MDC on the calling thread.
        AtomicReference<String> seen = new AtomicReference<>("sentinel");
        Runnable wrapped = MdcContextPropagator.wrap(() -> seen.set(MDC.get("requestId")));

        Thread t = new Thread(() -> {
            MDC.put("requestId", "worker");
            wrapped.run();
        });
        t.start();
        t.join();

        assertThat(seen.get()).isNull();
    }
}
