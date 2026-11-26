// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.SmartLifecycle;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionTimedOutException;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditAsyncWriterTest {

    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final RecordingStore store = new RecordingStore();
    private AuditAsyncWriter writer;

    @AfterEach
    void stop() {
        if (writer != null && writer.isRunning()) {
            writer.stop();
        }
    }

    @Test
    void aFullQueueDropsTheRowAndCountsIt() {
        writer = writer(2, 500, Duration.ofSeconds(1), Duration.ofSeconds(30), Duration.ofSeconds(5));

        writer.enqueue(row("a"));
        writer.enqueue(row("b"));
        writer.enqueue(row("c"));

        assertThat(dropped("queue_full")).isEqualTo(1);
        assertThat(metrics.get(AuditAsyncWriter.QUEUE_DEPTH_METRIC).gauge().value()).isEqualTo(2);
        assertThat(store.written()).isEmpty();
    }

    @Test
    void writesQueuedRowsInBatches() {
        writer = writer(100, 3, Duration.ofMillis(50), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();

        for (int i = 0; i < 7; i++) {
            writer.enqueue(row("row-" + i));
        }

        await().atMost(Duration.ofSeconds(5)).until(() -> store.written().size() == 7);
        assertThat(store.batchSizes()).allSatisfy(size -> assertThat(size).isBetween(1, 3));
        assertThat(store.written()).extracting(AuditEventRow::summary)
                .containsExactly("row-0", "row-1", "row-2", "row-3", "row-4", "row-5", "row-6");
        assertThat(dropped("queue_full") + dropped("write_failed") + dropped("closed")).isZero();
    }

    @Test
    void queuesRowsSanitised() {
        writer = writer(10, 500, Duration.ofSeconds(1), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();

        writer.enqueue(row("x".repeat(5000)));
        writer.stop();

        assertThat(store.written()).singleElement()
                .satisfies(row -> assertThat(row.summary()).hasSize(AuditSanitizer.TEXT_MAX));
    }

    @Test
    void aBatchThatKeepsFailingIsDroppedAfterTheRetryWindowAndCounted() {
        store.failing.set(true);
        writer = writer(100, 500, Duration.ofMillis(20), Duration.ofMillis(200), Duration.ofSeconds(5));
        writer.start();

        writer.enqueue(row("a"));
        writer.enqueue(row("b"));

        await().atMost(Duration.ofSeconds(5)).until(() -> dropped("write_failed") == 2);
        assertThat(store.attempts()).isGreaterThan(1);
    }

    @Test
    void aBatchThatFailsBrieflyIsRetriedAndWritten() {
        store.failing.set(true);
        writer = writer(100, 500, Duration.ofMillis(20), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();
        writer.enqueue(row("a"));
        await().atMost(Duration.ofSeconds(5)).until(() -> store.attempts() >= 2);

        store.failing.set(false);

        await().atMost(Duration.ofSeconds(5)).until(() -> store.written().size() == 1);
        assertThat(dropped("write_failed")).isZero();
    }

    @Test
    void stopDrainsWhatIsQueuedAndLaterRowsAreWrittenOnTheCallersThread() {
        // A flush interval far longer than the test: only the drain can write these rows.
        writer = writer(100, 2, Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();
        for (int i = 0; i < 5; i++) {
            writer.enqueue(row("queued-" + i));
        }

        writer.stop();

        assertThat(writer.isRunning()).isFalse();
        assertThat(store.written()).hasSize(5);
        assertThat(metrics.get(AuditAsyncWriter.QUEUE_DEPTH_METRIC).gauge().value()).isZero();

        writer.enqueue(row("late"));

        assertThat(store.written()).extracting(AuditEventRow::summary).last().isEqualTo("late");
        assertThat(dropped("closed")).isZero();
    }

    @Test
    void whatTheDrainBudgetCannotWriteIsCountedAsClosed() {
        store.delayMillis = 150;
        writer = writer(100, 1, Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofMillis(200));
        writer.start();
        for (int i = 0; i < 10; i++) {
            writer.enqueue(row("queued-" + i));
        }

        writer.stop();

        assertThat(store.written().size() + (int) dropped("closed")).isEqualTo(10);
        assertThat(dropped("closed")).isPositive();
    }

    @Test
    void stopsAfterEverythingElseInTheContext() {
        writer = writer(1, 1, Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1));

        assertThat(writer.getPhase()).isLessThan(0)
                .isLessThan(SmartLifecycle.DEFAULT_PHASE - 2048)
                .isGreaterThan(Integer.MIN_VALUE);
        assertThat(AuditAsyncWriter.drainBudget(Duration.ofSeconds(30))).isEqualTo(Duration.ofSeconds(10));
        assertThat(AuditAsyncWriter.drainBudget(Duration.ofSeconds(12))).isEqualTo(Duration.ofSeconds(6));
        assertThat(AuditAsyncWriter.drainBudget(Duration.ofSeconds(3))).isEqualTo(Duration.ofSeconds(1));
    }

    @Test
    void aBatchWithOneRefusedRowWritesTheOthersRowByRowAndRejectsOnlyThatOne() {
        store.refuse = row -> row.summary().equals("poison") ? "23514" : null;
        writer = writer(100, 10, Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();
        for (int i = 0; i < 10; i++) {
            writer.enqueue(row(i == 4 ? "poison" : "row-" + i));
        }

        writer.stop();

        assertThat(store.written()).hasSize(9).extracting(AuditEventRow::summary).doesNotContain("poison");
        assertThat(dropped("rejected")).isEqualTo(1);
        assertThat(dropped("write_failed")).isZero();
        assertThat(store.attempts()).as("one batch, then ten single rows").isEqualTo(11);
    }

    @Test
    void aRefusedRowIsNotRetriedForTheRetryWindow() {
        store.refuse = row -> row.summary().equals("poison") ? "22001" : null;
        writer = writer(100, 500, Duration.ofMillis(20), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();

        writer.enqueue(row("poison"));
        writer.enqueue(row("fine"));

        await().atMost(Duration.ofSeconds(2)).until(() -> dropped("rejected") == 1 && store.written().size() == 1);
    }

    @Test
    void aRowThatFailsBeforeReachingTheDatabaseIsRejectedAloneNotRetried() {
        store.failWith = row -> row.summary().equals("broken") ? new IllegalStateException("bad params") : null;
        writer = writer(100, 3, Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();

        writer.enqueue(row("a"));
        writer.enqueue(row("broken"));
        writer.enqueue(row("c"));

        await().atMost(Duration.ofSeconds(2)).until(() -> dropped("rejected") == 1 && store.written().size() == 2);
        assertThat(dropped("write_failed")).isZero();
    }

    @Test
    void wrongSqlRejectsTheWholeBatchAtOnce() {
        store.refuse = row -> "42703";
        writer = writer(100, 3, Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();

        writer.enqueue(row("a"));
        writer.enqueue(row("b"));
        writer.enqueue(row("c"));

        await().atMost(Duration.ofSeconds(2)).until(() -> dropped("rejected") == 3);
        assertThat(store.attempts()).as("not retried, not split").isEqualTo(1);
        assertThat(dropped("write_failed")).isZero();
    }

    @Test
    void failuresAreClassifiedBySqlStateClass() {
        assertThat(AuditAsyncWriter.classify(integrity("23505"))).isEqualTo(AuditAsyncWriter.Failure.REJECTED_DATA);
        assertThat(AuditAsyncWriter.classify(integrity("22P02"))).isEqualTo(AuditAsyncWriter.Failure.REJECTED_DATA);
        assertThat(AuditAsyncWriter.classify(integrity("42P01"))).isEqualTo(AuditAsyncWriter.Failure.CODE_BUG);
        assertThat(AuditAsyncWriter.classify(integrity("57014"))).isEqualTo(AuditAsyncWriter.Failure.TRANSIENT);
        assertThat(AuditAsyncWriter.classify(integrity("54000"))).isEqualTo(AuditAsyncWriter.Failure.REJECTED_DATA);
        assertThat(AuditAsyncWriter.classify(integrity("08006"))).isEqualTo(AuditAsyncWriter.Failure.TRANSIENT);
        assertThat(AuditAsyncWriter.classify(new DataAccessResourceFailureException("down")))
                .isEqualTo(AuditAsyncWriter.Failure.TRANSIENT);
        assertThat(AuditAsyncWriter.classify(new CannotCreateTransactionException("no connection")))
                .as("pool exhausted or database unreachable").isEqualTo(AuditAsyncWriter.Failure.TRANSIENT);
        assertThat(AuditAsyncWriter.classify(new TransactionTimedOutException("deadline")))
                .isEqualTo(AuditAsyncWriter.Failure.TRANSIENT);
        assertThat(AuditAsyncWriter.classify(new NullPointerException()))
                .as("building a row's parameters").isEqualTo(AuditAsyncWriter.Failure.REJECTED_DATA);
        assertThat(AuditAsyncWriter.classify(new IllegalStateException("details could not be serialised")))
                .isEqualTo(AuditAsyncWriter.Failure.REJECTED_DATA);
    }

    @Test
    void aLateRowAfterTheLateWindowIsDropped() throws InterruptedException {
        writer = writer(100, 500, Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofSeconds(5),
                Duration.ofMillis(50));
        writer.start();
        writer.stop();
        Thread.sleep(100);

        writer.enqueue(row("too late"));

        assertThat(store.written()).isEmpty();
        assertThat(dropped("closed")).isEqualTo(1);
    }

    @Test
    void aSecondLateRowWhileOneIsBeingWrittenIsDroppedNotQueued() {
        writer = writer(100, 500, Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofSeconds(5));
        writer.start();
        writer.stop();
        store.delayMillis = 500;

        CompletableFuture<Void> first = CompletableFuture.runAsync(() -> writer.enqueue(row("first late")));
        await().atMost(Duration.ofSeconds(2)).until(() -> store.attempts() == 1);
        long started = System.nanoTime();
        writer.enqueue(row("second late"));
        long waitedMillis = (System.nanoTime() - started) / 1_000_000;
        first.join();

        assertThat(waitedMillis).as("dropped at once, not queued behind the first").isLessThan(250);
        assertThat(dropped("closed")).isEqualTo(1);
        assertThat(store.written()).extracting(AuditEventRow::summary).containsExactly("first late");
    }

    private AuditAsyncWriter writer(int capacity, int batchSize, Duration flush, Duration retryFor, Duration drain) {
        return writer(capacity, batchSize, flush, retryFor, drain, Duration.ofSeconds(5));
    }

    private AuditAsyncWriter writer(int capacity, int batchSize, Duration flush, Duration retryFor, Duration drain,
                                    Duration lateWindow) {
        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenAnswer(invocation -> new SimpleTransactionStatus());
        return new AuditAsyncWriter(store, transactions, metrics, new AuditAsyncWriter.Settings(
                capacity, batchSize, flush, Duration.ofSeconds(5), retryFor, drain, lateWindow));
    }

    private static RuntimeException integrity(String sqlState) {
        SQLException cause = new SQLException("refused", sqlState);
        return sqlState.startsWith("42") ? new BadSqlGrammarException("insert", "INSERT ...", cause)
                : new DataIntegrityViolationException("refused", cause);
    }

    private double dropped(String reason) {
        return metrics.get(AuditAsyncWriter.DROPPED_METRIC).tag("reason", reason).counter().count();
    }

    private static AuditEventRow row(String summary) {
        return AuditSanitizerTest.row().summary(summary).build();
    }

    /** An AuditEventStore that keeps what it is given, and can fail or be slow on demand. */
    static final class RecordingStore extends AuditEventStore {

        final AtomicBoolean failing = new AtomicBoolean();
        volatile long delayMillis;
        /** The SQLState Postgres would refuse a row with, or null to accept it. */
        volatile java.util.function.Function<AuditEventRow, String> refuse = row -> null;
        /** An exception to throw before the database is reached, or null. */
        volatile java.util.function.Function<AuditEventRow, RuntimeException> failWith = row -> null;
        private final List<AuditEventRow> written = Collections.synchronizedList(new ArrayList<>());
        private final List<Integer> batchSizes = Collections.synchronizedList(new ArrayList<>());
        private volatile int attempts;

        RecordingStore() {
            super(null, mock(PlatformTransactionManager.class));
        }

        @Override
        public int insertAll(List<AuditEventRow> rows) {
            attempts++;
            if (delayMillis > 0) {
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (failing.get()) {
                throw new DataAccessResourceFailureException("database down");
            }
            for (AuditEventRow row : rows) {
                RuntimeException early = failWith.apply(row);
                if (early != null) {
                    throw early;
                }
                String state = refuse.apply(row);
                if (state != null) {
                    throw integrity(state);
                }
            }
            batchSizes.add(rows.size());
            written.addAll(rows);
            return rows.size();
        }

        List<AuditEventRow> written() {
            synchronized (written) {
                return List.copyOf(written);
            }
        }

        List<Integer> batchSizes() {
            synchronized (batchSizes) {
                return List.copyOf(batchSizes);
            }
        }

        int attempts() {
            return attempts;
        }
    }
}
