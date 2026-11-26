// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import io.micrometer.core.instrument.Metrics;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.time.Instant;

/**
 * The way rows reach {@code audit_events}, one method per write path:
 *
 * <table>
 *   <caption>Write paths</caption>
 *   <tr><th>Path</th><th>Method</th><th>Guarantee</th></tr>
 *   <tr><td>a change that succeeded</td><td>{@link #record}</td><td>in the caller's transaction: it
 *       commits or rolls back with the change, and a row that cannot be written fails the change</td></tr>
 *   <tr><td>CertPing's own change (an agent result, a job)</td><td>{@link #recordIsolated}</td><td>in the
 *       caller's transaction behind a savepoint: it commits with the change, and a row that cannot be written
 *       is handed to the async writer instead, so the audit trail never blocks the business state</td></tr>
 *   <tr><td>an attempt that failed</td><td>{@link #recordFailure}</td><td>through the bounded async
 *       writer, so the caller's rollback cannot take it and it never holds a second pool connection on a
 *       request thread</td></tr>
 *   <tr><td>a failure, or a staff read, that must be on record before the caller answers (an export refusal,
 *       a support export)</td>
 *       <td>{@link #recordFailureDurable}, {@link #recordDurable}</td><td>in a short transaction of its own;
 *       the caller learns whether it was written</td></tr>
 *   <tr><td>a sensitive read, an internal action</td><td>{@link #recordAsync}</td><td>through the
 *       bounded async writer</td></tr>
 * </table>
 *
 * <p>A request whose success row committed is marked ({@link #SUCCEEDED}), so a failure the same request
 * meets afterwards (a response that cannot be written, a later step throwing) is not also recorded as a
 * failure by {@link AuditFailures}: one request, one outcome.
 *
 * <p>Only {@link #record} can fail the caller; every other path drops and counts a row it cannot write
 * ({@code certping_audit_dropped_total}).
 */
@Slf4j
@Component
@DependsOnDatabaseInitialization
public class AuditRecorder {

    /** Rows {@link #recordIsolated} could not write in the caller's transaction and handed to the async writer. */
    static final String ISOLATED_FALLBACK_METRIC = "certping.audit.isolated.fallback";

    /** The request attribute marking a request whose success row committed. */
    static final String SUCCEEDED = AuditRecorder.class.getName() + ".SUCCEEDED";

    private final AuditEventStore store;
    private final AuditAsyncWriter asyncWriter;
    private final TransactionTemplate durableTransaction;
    private final DataSource dataSource;

    public AuditRecorder(AuditEventStore store, AuditAsyncWriter asyncWriter,
                         PlatformTransactionManager transactionManager, DataSource dataSource) {
        this.store = store;
        this.asyncWriter = asyncWriter;
        this.dataSource = dataSource;
        this.durableTransaction = new TransactionTemplate(transactionManager);
        this.durableTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.durableTransaction.setTimeout(2);
    }

    /**
     * Writes a success row in the caller's transaction.
     *
     * @throws org.springframework.transaction.IllegalTransactionStateException when no transaction is active
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuditEventRow row) {
        store.insert(row);
        markRequestSucceededOnCommit();
    }

    /**
     * Writes a row in the caller's transaction without letting it fail that transaction: for what CertPing records
     * about its own work (an agent's result, a job), where the business state must commit whatever happens to the
     * trail. The insert runs behind a JDBC savepoint on the transaction's connection (Spring's NESTED propagation
     * cannot do this: HibernateJpaDialect offers no savepoints). A write that fails, whether the database refuses it or
     * the row cannot even be prepared, is rolled back to the
     * savepoint, so the transaction stays usable, and the row is handed to the async writer, whose per-row handling
     * writes it or rejects it as poison; each fallback is counted in
     * {@code certping_audit_isolated_fallback_total{event}}. The row commits or rolls back with the change, as
     * {@link #record}'s does.
     *
     * <p>Only the insert is behind the savepoint: it executes no entity statements, so the persistence context needs
     * no flush and nothing pending is lost by the rollback.
     *
     * @throws org.springframework.transaction.IllegalTransactionStateException when no transaction is active
     * @throws RuntimeException only when the savepoint itself cannot be rolled back, which leaves the transaction
     *         unusable: the caller fails as it would have without the trail
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void recordIsolated(AuditEventRow row) {
        Connection connection = DataSourceUtils.getConnection(dataSource);
        try {
            Savepoint savepoint;
            try {
                savepoint = connection.setSavepoint();
            } catch (SQLException e) {
                fallBack(row, e);
                return;
            }
            try {
                store.insert(row);
            } catch (RuntimeException refused) {
                // A refusal of the database, or a row that failed before any SQL ran (its details could not be
                // serialised, a parameter could not be bound): rolling back to a savepoint no statement followed is
                // harmless, and either way the row goes to the async writer.
                try {
                    connection.rollback(savepoint);
                } catch (SQLException rollbackFailed) {
                    refused.addSuppressed(rollbackFailed);
                    throw refused;
                }
                release(connection, savepoint);
                fallBack(row, refused);
                return;
            }
            release(connection, savepoint);
            markRequestSucceededOnCommit();
        } finally {
            DataSourceUtils.releaseConnection(connection, dataSource);
        }
    }

    private void fallBack(AuditEventRow row, Exception cause) {
        Metrics.counter(ISOLATED_FALLBACK_METRIC, "event", row.event() == null ? "none" : row.event()).increment();
        log.warn("[AuditRecorder] {} could not be written with its change ({}); handed to the async writer",
                row.event(), cause.getClass().getSimpleName());
        asyncWriter.enqueue(row);
    }

    private static void release(Connection connection, Savepoint savepoint) {
        try {
            connection.releaseSavepoint(savepoint);
        } catch (SQLException ignored) {
            // Released with the transaction's end; PostgreSQL keeps no more than the name until then.
        }
    }

    /** Marks the current request once the transaction holding its success row commits; never on rollback. */
    private static void markRequestSucceededOnCommit() {
        RequestAttributes request = RequestContextHolder.getRequestAttributes();
        if (request == null || !TransactionSynchronizationManager.isSynchronizationActive()) {
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status == STATUS_COMMITTED) {
                    try {
                        request.setAttribute(SUCCEEDED, Boolean.TRUE, RequestAttributes.SCOPE_REQUEST);
                    } catch (IllegalStateException requestEnded) {
                        // The request is over: nothing left to mark.
                    }
                }
            }
        });
    }

    /**
     * Queues a failure row for the async writer. Call it whether or not the caller's transaction is still
     * open: the row is written in a transaction of its own, after the rollback.
     */
    public void recordFailure(AuditEventRow row) {
        asyncWriter.enqueue(row);
    }

    /**
     * Writes a failure row now, in a transaction of its own bounded to two seconds, for a refusal that must
     * not be served unless it is on record. Call it after the caller's transaction has closed: inside it,
     * it holds a second pool connection while the first waits.
     *
     * @return whether the row was written; a row that was not is counted as {@code write_failed}
     */
    public boolean recordFailureDurable(AuditEventRow row) {
        return recordDurable(row);
    }

    /**
     * Writes a row now, in a transaction of its own bounded to two seconds: for a read that must not be served
     * unless it is on record (a staff export of a customer's trail). Call it outside the caller's transaction.
     *
     * @return whether the row was written; a row that was not is counted as {@code write_failed}
     */
    public boolean recordDurable(AuditEventRow row) {
        try {
            durableTransaction.executeWithoutResult(status -> store.insert(row));
            return true;
        } catch (RuntimeException e) {
            asyncWriter.lost(AuditAsyncWriter.DropReason.WRITE_FAILED, 1, e);
            return false;
        }
    }

    /**
     * Whether a row of {@code type} about {@code resourceRef} was written in {@code organizationId}'s trail since
     * {@code since}, on the caller's transaction when there is one: lets a job that every pod runs write a repeated
     * observation once per window across the cluster, not once per pod.
     */
    public boolean recordedSince(long organizationId, AuditEventType type, String resourceRef, Instant since) {
        return store.existsSince(organizationId, type.key(), type.resourceType().name(), resourceRef, since);
    }

    /** Queues a row for the async writer: sensitive reads and internal actions. */
    public void recordAsync(AuditEventRow row) {
        asyncWriter.enqueue(row);
    }
}
