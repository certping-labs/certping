// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.core.task.TaskDecorator;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class AsyncMdcConfigTest {

    private final AsyncMdcConfig config = new AsyncMdcConfig();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void mdcTaskDecorator_isNonNull() {
        assertThat(config.mdcTaskDecorator()).isNotNull();
    }

    @Test
    void mdcTaskDecorator_propagatesMdcToWorkerThread() throws Exception {
        TaskDecorator decorator = config.mdcTaskDecorator();
        MDC.put("requestId", "req-async");
        AtomicReference<String> seen = new AtomicReference<>();
        Runnable decorated = decorator.decorate(() -> seen.set(MDC.get("requestId")));

        // Run on a separate thread; the decorator must carry the MDC over even though the worker
        // thread itself starts with an empty MDC.
        Thread worker = new Thread(decorated);
        worker.start();
        worker.join();

        assertThat(seen.get()).isEqualTo("req-async");
    }
}
