// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.config.QueueAlertProperties;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.QueueAlertStateEntity;
import com.certmanagement.messaging.OperationalAlertPublisher;
import com.certmanagement.messaging.transport.PostgresMessageQueue;
import com.certmanagement.repository.QueueAlertStateRepository;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

/**
 * Reads the message counts (active and dead-lettered) of a configured set of message queue
 * channels and emails the super admin when a threshold is breached, and again when it recovers. An
 * operational health signal only: permanent cert failures already emit {@code AGENT_ERROR} at
 * dead-letter time, so this never drives tenant-facing notification.
 *
 * <p>Own {@code @Scheduled} entry-point, two-tier kill switch (static env
 * {@code certping.jobs.queue-alert.enabled} + dynamic {@link FeatureFlags#QUEUE_DEPTH_ALERTS}) and a
 * per-run {@code correlationId}. Reads are counts from {@link PostgresMessageQueue#depth(String)};
 * no message is received.
 *
 * <p><b>Multi-replica:</b> the server has no leader election, so every transition is driven through
 * the atomic conditional UPDATEs on {@link QueueAlertStateRepository}; only the replica whose claim
 * affects one row sends the email. {@link #evaluate} is the pure, unit-tested spec of that logic.
 */
@Slf4j
@Service
public class QueueDepthAlertService {

    enum AlertDecision { FIRE, RECOVER, NONE }

    static final String METRIC_ACTIVE = "ACTIVE";
    static final String METRIC_DLQ    = "DLQ";

    private static final String ACTION_ACTIVE   = "SYSTEM_QUEUE_DEPTH_WARNING";
    private static final String ACTION_DLQ      = "SYSTEM_DLQ_ALERT";
    private static final String ACTION_RESOLVED = "SYSTEM_QUEUE_ALERT_RESOLVED";

    /** Entity type reported in the alert; every watched entity is a message queue channel. */
    private static final String ENTITY_TYPE = "QUEUE";

    private final PostgresMessageQueue queue;
    private final SchedulerExecutionPolicy executionPolicy;
    private final QueueAlertProperties props;
    private final QueueAlertStateRepository stateRepo;
    private final OperationalAlertPublisher publisher;

    public QueueDepthAlertService(PostgresMessageQueue queue,
                                  SchedulerExecutionPolicy executionPolicy,
                                  QueueAlertProperties props,
                                  QueueAlertStateRepository stateRepo,
                                  OperationalAlertPublisher publisher) {
        this.queue = queue;
        this.executionPolicy = executionPolicy;
        this.props = props;
        this.stateRepo = stateRepo;
        this.publisher = publisher;
    }

    /**
     * Scheduled entry-point. Gated by the {@code queue-alert} entry of {@link JobPolicy}: a static
     * env kill switch plus the dynamic {@link FeatureFlags#QUEUE_DEPTH_ALERTS} platform flag.
     */
    @RegisteredJob("queue-alert")
    @Scheduled(cron = "${certping.jobs.queue-alert.cron}", zone = "UTC")
    public void runQueueDepthChecks() {
        if (!executionPolicy.canRun("queue-alert")) {
            return;
        }
        if (props.getEntities() == null || props.getEntities().isEmpty()) {
            log.debug("[QueueDepthAlertService] no entities configured under certping.alerts.queue-depth.entities — nothing to check");
            return;
        }

        String correlationId = "corr-cron-queue-alert-" + UUID.randomUUID();
        String parentMdcCorrelationId = MDC.get("correlationId");
        MDC.put("correlationId", correlationId);
        try {
            for (QueueAlertProperties.Entity entity : props.getEntities()) {
                checkEntity(entity);
            }
        } finally {
            if (parentMdcCorrelationId != null) {
                MDC.put("correlationId", parentMdcCorrelationId);
            } else {
                MDC.remove("correlationId");
            }
        }
    }

    /**
     * Reads both counts for one channel and evaluates the ACTIVE and DLQ metrics independently.
     * ACTIVE counts ready and locked messages; DLQ counts dead-lettered ones.
     */
    private void checkEntity(QueueAlertProperties.Entity entity) {
        String key = entity.entityKey();
        long active;
        long dlq;
        try {
            Map<String, Long> depth = queue.depth(entity.getName());
            active = depth.getOrDefault("READY", 0L) + depth.getOrDefault("LEASED", 0L);
            dlq = depth.getOrDefault("DEAD", 0L);
        } catch (Exception e) {
            log.error("[QueueDepthAlertService] failed to read message counts for channel '{}': {}",
                    key, e.getMessage(), e);
            return; // one bad entity must not abort the rest of the sweep
        }

        long activeThreshold = entity.getActiveThreshold() != null
                ? entity.getActiveThreshold() : props.getDefaultActiveThreshold();
        long dlqThreshold = entity.getDlqThreshold() != null
                ? entity.getDlqThreshold() : props.getDefaultDlqThreshold();

        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        evaluateAndAct(key, ENTITY_TYPE, METRIC_ACTIVE, active, activeThreshold, ACTION_ACTIVE, "WARNING", now);
        evaluateAndAct(key, ENTITY_TYPE, METRIC_DLQ, dlq, dlqThreshold, ACTION_DLQ, "CRITICAL", now);
    }

    private void evaluateAndAct(String entityKey, String entityType, String metric, long value,
                                long threshold, String alertAction, String severity, OffsetDateTime now) {
        if (threshold <= 0) {
            return; // metric disabled for this entity
        }
        stateRepo.ensureRow(entityKey, metric, now);
        QueueAlertStateEntity row = stateRepo.findByEntityNameAndMetric(entityKey, metric).orElse(null);
        boolean alerting = row != null && "ALERTING".equals(row.getAlertState());
        OffsetDateTime lastAlertedAt = row != null ? row.getLastAlertedAt() : null;

        switch (evaluate(value, threshold, alerting, lastAlertedAt, now, props.getCooldownMinutes())) {
            case FIRE -> {
                OffsetDateTime cutoff = now.minusMinutes(Math.max(0, props.getCooldownMinutes()));
                if (stateRepo.claimFire(entityKey, metric, value, now, cutoff) == 1) {
                    log.warn("QueueAlert FIRE entity={} metric={} value={} threshold={} severity={}",
                            entityKey, metric, value, threshold, severity);
                    publisher.publishQueueAlert(alertAction, entityKey, entityType, metric, value, threshold, severity);
                }
            }
            case RECOVER -> {
                if (stateRepo.claimRecover(entityKey, metric, value, now) == 1) {
                    log.info("QueueAlert RECOVER entity={} metric={} value={} threshold={}",
                            entityKey, metric, value, threshold);
                    publisher.publishQueueAlert(ACTION_RESOLVED, entityKey, entityType, metric, value, threshold, "INFO");
                }
            }
            case NONE -> { /* steady state — nothing to do */ }
        }
    }

    /**
     * Pure alert decision (unit-tested). The {@link QueueAlertStateRepository} claim queries
     * re-encode the same guard atomically for cross-replica single-fire; this is the spec.
     *
     * <ul>
     *   <li>breached &amp; not already alerting (or no prior alert)        → {@code FIRE} (new),</li>
     *   <li>breached &amp; alerting &amp; cooldown elapsed                  → {@code FIRE} (re-alert),</li>
     *   <li>breached &amp; alerting &amp; within cooldown                   → {@code NONE},</li>
     *   <li>not breached &amp; alerting                                     → {@code RECOVER},</li>
     *   <li>not breached &amp; not alerting                                 → {@code NONE}.</li>
     * </ul>
     */
    static AlertDecision evaluate(long value, long threshold, boolean currentlyAlerting,
                                  OffsetDateTime lastAlertedAt, OffsetDateTime now, int cooldownMinutes) {
        boolean breached = threshold > 0 && value >= threshold;
        if (breached) {
            if (!currentlyAlerting || lastAlertedAt == null) {
                return AlertDecision.FIRE;
            }
            if (!lastAlertedAt.isAfter(now.minusMinutes(Math.max(0, cooldownMinutes)))) {
                return AlertDecision.FIRE; // cooldown fully elapsed → re-alert
            }
            return AlertDecision.NONE;
        }
        return currentlyAlerting ? AlertDecision.RECOVER : AlertDecision.NONE;
    }
}
