// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

class MdcContextPropagatorTest {

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void wrapRunnable_carriesMdcToWorkerThread() throws Exception {
        MDC.put("requestId", "req-1");
        MDC.put("correlationId", "corr-1");
        AtomicReference<String> seenReq = new AtomicReference<>();
        AtomicReference<String> seenCorr = new AtomicReference<>();
        Runnable task = MdcContextPropagator.wrap(() -> {
            seenReq.set(MDC.get("requestId"));
            seenCorr.set(MDC.get("correlationId"));
        });
        // Run on a different thread to prove propagation isn't an artefact of running inline.
        Thread t = new Thread(task);
        t.start();
        t.join();
        assertThat(seenReq.get()).isEqualTo("req-1");
        assertThat(seenCorr.get()).isEqualTo("corr-1");
    }

    @Test
    void wrapRunnable_restoresPreviousMdcOnWorkerThreadAfterRun() throws Exception {
        // Simulate a pooled worker thread that already has some MDC; wrap should restore it.
        AtomicReference<String> beforeRun = new AtomicReference<>();
        AtomicReference<String> afterRun = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            MDC.put("requestId", "worker-existing");
            beforeRun.set(MDC.get("requestId"));
        });
        worker.start();
        worker.join();

        // Caller sets its own MDC; wrap captures it; runs on a worker that has a different value.
        MDC.put("requestId", "caller");
        Runnable task = MdcContextPropagator.wrap(() -> {
            assertThat(MDC.get("requestId")).isEqualTo("caller");
        });
        Thread workerTwo = new Thread(() -> {
            MDC.put("requestId", "worker-existing");
            task.run();
            afterRun.set(MDC.get("requestId"));
        });
        workerTwo.start();
        workerTwo.join();

        assertThat(beforeRun.get()).isEqualTo("worker-existing");
        // After the wrapped task returns, the worker's prior MDC must be restored, not cleared
        // to the caller's value or to empty.
        assertThat(afterRun.get()).isEqualTo("worker-existing");
    }

    @Test
    void wrapRunnable_emptyCallerMdc_clearsWorkerMdcForTaskAndRestoresAfter() throws Exception {
        MDC.clear();
        AtomicReference<String> insideTask = new AtomicReference<>();
        AtomicReference<String> afterTask = new AtomicReference<>();
        Runnable task = MdcContextPropagator.wrap(() -> insideTask.set(MDC.get("requestId")));
        Thread worker = new Thread(() -> {
            MDC.put("requestId", "leftover");
            task.run();
            afterTask.set(MDC.get("requestId"));
        });
        worker.start();
        worker.join();
        assertThat(insideTask.get()).isNull();
        assertThat(afterTask.get()).isEqualTo("leftover");
    }

    @Test
    void wrapCallable_carriesMdcAndReturnsValue() throws Exception {
        MDC.put("requestId", "req-call");
        // Disambiguate the overload by typing the lambda explicitly — bare `() -> ...` matches
        // both wrap(Callable) and wrap(Supplier).
        Callable<String> raw = () -> MDC.get("requestId") + "-done";
        Callable<String> task = MdcContextPropagator.wrap(raw);
        String result = Executors.newSingleThreadExecutor().submit(task).get();
        assertThat(result).isEqualTo("req-call-done");
    }

    @Test
    void wrapSupplier_carriesMdcAcrossCompletableFuture() throws Exception {
        MDC.put("requestId", "req-sup");
        Supplier<String> raw = () -> MDC.get("requestId");
        Supplier<String> task = MdcContextPropagator.wrap(raw);
        String result = CompletableFuture.supplyAsync(task).get();
        assertThat(result).isEqualTo("req-sup");
    }
}
