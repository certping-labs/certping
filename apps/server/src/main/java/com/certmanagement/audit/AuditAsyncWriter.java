// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.SmartLifecycle;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Writes the rows that are not part of a caller's transaction (failures, reads, internal actions) off
 * the caller's thread. It replaces an unbounded
 * executor queue with a bounded one: {@link #enqueue} never blocks, and a row that cannot be queued or
 * written is dropped and counted, never allowed to fail or slow the work it describes.
 *
 * <ul>
 *   <li>One daemon thread writes the queue in JDBC batches of up to {@code batch-size} rows, at least
 *       every {@code flush-interval}, each batch in its own transaction bounded by {@code write-timeout}.</li>
 *   <li>A batch that fails for a reason that can pass (connection, timeout, failover) is retried until
 *       {@code retry-for} has passed, then dropped; meanwhile the queue keeps filling up to its capacity
 *       (sized for about a minute of a Postgres failover).</li>
 *   <li>A batch Postgres refuses for its data (SQLState class 22, 23 or 54), or that fails for a reason
 *       that is not a data-access one (building a row's parameters), is never retried as a whole: it
 *       is written again row by row, each in a short transaction of its own (a failed statement aborts
 *       the transaction it is in), and only the rows refused again are dropped, as {@code rejected}.
 *       Class 42 (the SQL itself is wrong) is a code bug no row can pass: the whole batch is rejected.</li>
 *   <li>Losses are counted as
 *       {@code certping_audit_dropped_total{reason=queue_full|write_failed|rejected|closed}} and logged at
 *       ERROR at most once a minute, naming the event key and SQLState, never a row's values;
 *       {@code certping_audit_queue_depth} is the backlog.</li>
 *   <li>Its {@link #PHASE} is the lowest of the context, so it stops after the web server's graceful
 *       shutdown, the gRPC server and the schedulers, and drains what they queued within
 *       min(timeout-per-shutdown-phase - 6s, 10s).</li>
 *   <li>A row that arrives after the drain (a message consumer closed later, at bean destruction) is
 *       written on the caller's thread, for {@code late-window} (5s) after stop and one at a time: a
 *       second late row while one is being written, or any after the window, is dropped as
 *       {@code closed}, never queued. The one late write in flight can block its caller for up to
 *       Hikari's {@code connection-timeout} while it waits for a connection; that is accepted, as it
 *       happens only during shutdown and to one thread.</li>
 * </ul>
 */
@Slf4j
@Component
public class AuditAsyncWriter implements SmartLifecycle {

    /** Stops last: after everything that can still produce rows during shutdown. */
    public static final int PHASE = Integer.MIN_VALUE + 1024;

    static final String DROPPED_METRIC = "certping.audit.dropped";
    static final String QUEUE_DEPTH_METRIC = "certping.audit.queue.depth";
    private static final long LOSS_LOG_EVERY_NANOS = TimeUnit.MINUTES.toNanos(1);
    /** The writer waits in slices no longer than this, so stop() is noticed at once whatever the flush interval. */
    private static final long STOP_CHECK_NANOS = TimeUnit.MILLISECONDS.toNanos(100);

    /** Why a row was not written; the tag value of the dropped counter. */
    public enum DropReason {
        QUEUE_FULL("queue_full"),
        WRITE_FAILED("write_failed"),
        REJECTED("rejected"),
        CLOSED("closed");

        private final String tag;

        DropReason(String tag) {
            this.tag = tag;
        }

        public String tag() {
            return tag;
        }
    }

    /**
     * @param drainBudget how long {@link #stop()} may spend writing what is queued
     * @param lateWindow  how long after stop a late row is still written on its caller's thread
     */
    record Settings(int capacity, int batchSize, Duration flushInterval, Duration writeTimeout, Duration retryFor,
                    Duration drainBudget, Duration lateWindow) {
    }

    /** What a failed write says about its rows. */
    enum Failure {
        /** May pass on a later attempt: connection, timeout, failover. */
        TRANSIENT,
        /**
         * Some row is bad, the rest may be fine: Postgres refused the data (class 22, 23 or 54), or the
         * write failed outside data access (building a row's parameters).
         */
        REJECTED_DATA,
        /** The SQL itself is wrong (class 42): no row can be written until the code is fixed. */
        CODE_BUG
    }

    private final AuditEventStore store;
    private final Settings settings;
    private final ArrayBlockingQueue<AuditEventRow> queue;
    private final TransactionTemplate batchTransaction;
    private final TransactionTemplate lateTransaction;
    private final Map<DropReason, Counter> dropped = new EnumMap<>(DropReason.class);
    /** Read-held by every enqueue, so none can queue a row after {@link #stop()} has started draining. */
    private final ReentrantReadWriteLock closing = new ReentrantReadWriteLock();
    private final AtomicLong lostSinceStart = new AtomicLong();
    private final AtomicLong lastLossLog = new AtomicLong(System.nanoTime() - LOSS_LOG_EVERY_NANOS);
    private final AtomicLong rejectedSinceStart = new AtomicLong();
    private final AtomicLong lastRejectLog = new AtomicLong(System.nanoTime() - LOSS_LOG_EVERY_NANOS);
    /** One late write at a time; a second late row is dropped rather than queued behind it. */
    private final Semaphore lateWrite = new Semaphore(1);
    private volatile long lateDeadline;

    private volatile boolean closed;
    private volatile boolean running;
    private Thread writer;

    @Autowired
    public AuditAsyncWriter(AuditEventStore store, PlatformTransactionManager transactionManager,
                            MeterRegistry meterRegistry,
                            @Value("${certping.audit.async.queue-capacity:10000}") int capacity,
                            @Value("${certping.audit.async.batch-size:500}") int batchSize,
                            @Value("${certping.audit.async.flush-interval:1s}") Duration flushInterval,
                            @Value("${certping.audit.async.write-timeout:5s}") Duration writeTimeout,
                            @Value("${certping.audit.async.retry-for:30s}") Duration retryFor,
                            @Value("${certping.audit.async.late-window:5s}") Duration lateWindow,
                            @Value("${spring.lifecycle.timeout-per-shutdown-phase:30s}") Duration shutdownPhase) {
        this(store, transactionManager, meterRegistry, new Settings(capacity, batchSize, flushInterval, writeTimeout,
                retryFor, drainBudget(shutdownPhase), lateWindow));
    }

    AuditAsyncWriter(AuditEventStore store, PlatformTransactionManager transactionManager, MeterRegistry meterRegistry,
                     Settings settings) {
        this.store = store;
        this.settings = settings;
        this.queue = new ArrayBlockingQueue<>(settings.capacity());
        this.batchTransaction = ownTransaction(transactionManager, settings.writeTimeout());
        this.lateTransaction = ownTransaction(transactionManager, Duration.ofSeconds(2));
        for (DropReason reason : DropReason.values()) {
            dropped.put(reason, Counter.builder(DROPPED_METRIC)
                    .description("Audit rows that were not written")
                    .tag("reason", reason.tag())
                    .register(meterRegistry));
        }
        Gauge.builder(QUEUE_DEPTH_METRIC, queue, ArrayBlockingQueue::size)
                .description("Audit rows waiting to be written")
                .register(meterRegistry);
    }

    /**
     * Queues the row and returns at once. A full queue drops it and counts it. The row is queued
     * sanitised, so a backlog holds values cut to their limits, not whole request headers.
     */
    public void enqueue(AuditEventRow row) {
        AuditEventRow clean = AuditSanitizer.sanitize(row);
        closing.readLock().lock();
        try {
            if (!closed) {
                if (!queue.offer(clean)) {
                    lost(DropReason.QUEUE_FULL, 1, null);
                }
                return;
            }
        } finally {
            closing.readLock().unlock();
        }
        writeLate(clean);
    }

    /** Counts rows another write path could not write, such as a durable failure row. */
    public void lost(DropReason reason, int rows, Throwable error) {
        dropped.get(reason).increment(rows);
        long total = lostSinceStart.addAndGet(rows);
        long now = System.nanoTime();
        long last = lastLossLog.get();
        if (now - last >= LOSS_LOG_EVERY_NANOS && lastLossLog.compareAndSet(last, now)) {
            // The exception's class and SQL state only: a refused row's message can quote its values.
            log.error("[AuditAsyncWriter] {} audit row(s) lost ({}); {} lost since start; cause={}",
                    rows, reason.tag(), total, describe(error));
        }
    }

    @Override
    public synchronized void start() {
        if (running) {
            return;
        }
        closed = false;
        Thread thread = new Thread(this::run, "audit-writer");
        thread.setDaemon(true);
        writer = thread;
        running = true;
        thread.start();
    }

    /**
     * Stops taking rows into the queue and writes what is queued, within the drain budget; what is left
     * when it ends is counted as {@code closed}.
     */
    @Override
    public void stop() {
        closing.writeLock().lock();
        try {
            lateDeadline = System.nanoTime() + settings.lateWindow().toNanos();
            closed = true;
        } finally {
            closing.writeLock().unlock();
        }
        Thread thread;
        synchronized (this) {
            thread = writer;
        }
        if (thread != null) {
            try {
                thread.join(settings.drainBudget().plus(settings.writeTimeout()).plus(settings.flushInterval()).toMillis());
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        int stranded = queue.size();
        if (stranded > 0) {
            queue.clear();
            lost(DropReason.CLOSED, stranded, null);
        }
        running = false;
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return PHASE;
    }

    private void run() {
        List<AuditEventRow> batch = new ArrayList<>(settings.batchSize());
        long flushNanos = settings.flushInterval().toNanos();
        long deadline = 0;
        long failingSince = 0;
        Throwable lastError = null;
        while (!closed) {
            if (failingSince == 0 && batch.size() < settings.batchSize()) {
                long wait = batch.isEmpty() ? flushNanos : Math.max(0, deadline - System.nanoTime());
                AuditEventRow row = poll(Math.min(wait, STOP_CHECK_NANOS));
                if (row != null) {
                    if (batch.isEmpty()) {
                        deadline = System.nanoTime() + flushNanos;
                    }
                    batch.add(row);
                    queue.drainTo(batch, settings.batchSize() - batch.size());
                }
                if (!batch.isEmpty() && batch.size() < settings.batchSize() && System.nanoTime() < deadline) {
                    continue;
                }
            } else {
                pauseUnlessClosed(flushNanos);
            }
            if (batch.isEmpty()) {
                continue;
            }
            lastError = writeBatch(batch);
            if (lastError == null) {
                failingSince = 0;
            } else if (failingSince == 0) {
                failingSince = System.nanoTime();
            } else if (System.nanoTime() - failingSince >= settings.retryFor().toNanos()) {
                lost(DropReason.WRITE_FAILED, batch.size(), lastError);
                batch.clear();
                failingSince = 0;
            }
        }
        drain(batch);
    }

    /** Writes the batch and everything queued, in batches, until the queue is empty or the budget ends. */
    private void drain(List<AuditEventRow> batch) {
        long deadline = System.nanoTime() + settings.drainBudget().toNanos();
        while (true) {
            queue.drainTo(batch, settings.batchSize() - batch.size());
            if (batch.isEmpty()) {
                return;
            }
            if (System.nanoTime() >= deadline) {
                lost(DropReason.CLOSED, batch.size(), null);
                return;
            }
            Throwable error = writeBatch(batch);
            if (error != null) {
                lost(DropReason.WRITE_FAILED, batch.size(), error);
            }
            batch.clear();
        }
    }

    /**
     * Writes the batch and takes off it every row written or rejected; returns the error to retry on
     * when rows are left, or null when none are.
     */
    private Throwable writeBatch(List<AuditEventRow> batch) {
        Throwable error = write(batch);
        if (error == null) {
            batch.clear();
            return null;
        }
        switch (classify(error)) {
            case CODE_BUG -> {
                rejected(batch, error);
                batch.clear();
                return null;
            }
            case REJECTED_DATA -> {
                return writeEach(batch);
            }
            default -> {
                return error;
            }
        }
    }

    /**
     * Writes the rows one by one, each in a transaction of its own, so a refused row cannot take the
     * others with it. A row refused again is rejected; a transient failure stops the pass and leaves the
     * rest of the batch for the retry.
     */
    private Throwable writeEach(List<AuditEventRow> batch) {
        Iterator<AuditEventRow> rows = batch.iterator();
        while (rows.hasNext()) {
            AuditEventRow row = rows.next();
            Throwable error = write(List.of(row));
            if (error != null && classify(error) == Failure.TRANSIENT) {
                return error;
            }
            if (error != null) {
                rejected(List.of(row), error);
            }
            rows.remove();
        }
        return null;
    }

    /** Counts rows Postgres will never accept, and says which events and why, never what they held. */
    private void rejected(List<AuditEventRow> rows, Throwable error) {
        dropped.get(DropReason.REJECTED).increment(rows.size());
        long total = rejectedSinceStart.addAndGet(rows.size());
        long now = System.nanoTime();
        long last = lastRejectLog.get();
        if (now - last >= LOSS_LOG_EVERY_NANOS && lastRejectLog.compareAndSet(last, now)) {
            List<String> events = rows.stream().map(row -> row.event() == null ? row.action() : row.event())
                    .distinct().limit(10).toList();
            log.error("[AuditAsyncWriter] {} audit row(s) rejected by the database ({}): events={} sqlState={};"
                            + " {} rejected since start",
                    rows.size(), classify(error), events, sqlState(error), total);
        }
    }

    /**
     * What a failed write means for its rows. With an SQLState: classes 22 (data), 23 (constraint) and 54
     * (a limit exceeded, e.g. a value too large) are the rows' fault, 42 is the SQL's, and anything else
     * (connection 08, timeout and shutdown 57, resources 53, serialization 40) may pass. Without one, a
     * Spring data-access or transaction failure is the connection, the pool or a timeout and may pass;
     * anything else (an NPE or IllegalStateException while building a row's parameters) is a bad row.
     */
    static Failure classify(Throwable error) {
        String state = sqlState(error);
        if (state != null && state.length() >= 2) {
            return switch (state.substring(0, 2)) {
                case "22", "23", "54" -> Failure.REJECTED_DATA;
                case "42" -> Failure.CODE_BUG;
                default -> Failure.TRANSIENT;
            };
        }
        return error instanceof DataAccessException || error instanceof TransactionException
                ? Failure.TRANSIENT : Failure.REJECTED_DATA;
    }

    private static String sqlState(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sql && sql.getSQLState() != null) {
                return sql.getSQLState();
            }
        }
        return null;
    }

    /** Null when the batch was written. */
    private Throwable write(List<AuditEventRow> batch) {
        try {
            batchTransaction.executeWithoutResult(status -> store.insertAll(batch));
            return null;
        } catch (RuntimeException e) {
            return e;
        }
    }

    /**
     * After {@link #stop()}: within the late window, and only when no other late write is in flight, the
     * row is written on the caller's thread in a short transaction of its own; otherwise it is dropped.
     */
    private void writeLate(AuditEventRow row) {
        if (System.nanoTime() - lateDeadline > 0 || !lateWrite.tryAcquire()) {
            lost(DropReason.CLOSED, 1, null);
            return;
        }
        try {
            lateTransaction.executeWithoutResult(status -> store.insert(row));
        } catch (RuntimeException e) {
            lost(DropReason.CLOSED, 1, e);
        } finally {
            lateWrite.release();
        }
    }

    private AuditEventRow poll(long nanos) {
        try {
            return queue.poll(nanos, TimeUnit.NANOSECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    private void pauseUnlessClosed(long nanos) {
        long until = System.nanoTime() + nanos;
        try {
            for (long left = nanos; left > 0 && !closed; left = until - System.nanoTime()) {
                TimeUnit.NANOSECONDS.sleep(Math.min(left, STOP_CHECK_NANOS));
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static TransactionTemplate ownTransaction(PlatformTransactionManager transactionManager, Duration timeout) {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template.setTimeout((int) Math.max(1, timeout.toSeconds()));
        return template;
    }

    /**
     * The shutdown phase's budget less 6s (one flush and one write, so the drain ends inside it), and at
     * most 10s: a drain longer than that is a backlog shutdown should not wait on. At least 1s.
     */
    static Duration drainBudget(Duration shutdownPhase) {
        Duration budget = shutdownPhase.minusSeconds(6);
        if (budget.compareTo(Duration.ofSeconds(10)) > 0) {
            return Duration.ofSeconds(10);
        }
        return budget.compareTo(Duration.ofSeconds(1)) < 0 ? Duration.ofSeconds(1) : budget;
    }

    private static String describe(Throwable error) {
        if (error == null) {
            return "-";
        }
        String state = sqlState(error);
        return state == null ? error.getClass().getSimpleName() : error.getClass().getSimpleName() + " sqlState=" + state;
    }
}
