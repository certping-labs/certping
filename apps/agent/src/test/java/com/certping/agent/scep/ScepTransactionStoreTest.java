// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScepTransactionStoreTest {

    @Test
    void concurrentSameCsrCallsShareOneExecutionAndResponse() throws Exception {
        ScepTransactionStore store = new ScepTransactionStore(new AgentProperties());
        AtomicInteger executions = new AtomicInteger();
        CountDownLatch operationStarted = new CountDownLatch(1);
        CountDownLatch releaseOperation = new CountDownLatch(1);
        BinaryResponse expected = new BinaryResponse(
                ScepConstants.CT_PKI_MESSAGE, "response".getBytes(StandardCharsets.UTF_8));

        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> store.execute("source-a", "tx-1", "csr-a", () -> {
                executions.incrementAndGet();
                operationStarted.countDown();
                await(releaseOperation);
                return expected;
            }));
            assertThat(operationStarted.await(2, TimeUnit.SECONDS)).isTrue();
            var second = executor.submit(() -> store.execute(
                    "source-a", "tx-1", "csr-a", () -> {
                        executions.incrementAndGet();
                        return expected;
                    }));

            // A coalesced follower remains blocked on the leader's future until the leader exits.
            Thread.sleep(100);
            assertThat(second.isDone()).isFalse();

            releaseOperation.countDown();

            assertThat(first.get(2, TimeUnit.SECONDS)).isSameAs(expected);
            assertThat(second.get(2, TimeUnit.SECONDS)).isSameAs(expected);
            assertThat(executions).hasValue(1);
        }
    }

    @Test
    void concurrentDifferentCsrFailsWithoutExecutingFollower() throws Exception {
        ScepTransactionStore store = new ScepTransactionStore(new AgentProperties());
        CountDownLatch operationStarted = new CountDownLatch(1);
        CountDownLatch releaseOperation = new CountDownLatch(1);
        AtomicInteger followerExecutions = new AtomicInteger();

        try (var executor = Executors.newSingleThreadExecutor()) {
            var leader = executor.submit(() -> store.execute("source-a", "tx-1", "csr-a", () -> {
                operationStarted.countDown();
                await(releaseOperation);
                return new BinaryResponse("type", new byte[]{1});
            }));
            assertThat(operationStarted.await(2, TimeUnit.SECONDS)).isTrue();

            assertThatThrownBy(() -> store.execute("source-a", "tx-1", "csr-b", () -> {
                followerExecutions.incrementAndGet();
                return new BinaryResponse("type", new byte[]{2});
            })).isInstanceOf(ScepConflictException.class);

            releaseOperation.countDown();
            leader.get(2, TimeUnit.SECONDS);
            assertThat(followerExecutions).hasValue(0);
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(2, TimeUnit.SECONDS)) {
                throw new IllegalStateException("test latch timed out");
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("test interrupted", exception);
        }
    }
}
