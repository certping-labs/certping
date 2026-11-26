// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.service.scheduler.QueueDepthAlertService.AlertDecision;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class QueueDepthAlertServiceTest {

    private static final OffsetDateTime NOW = OffsetDateTime.of(2026, 6, 22, 12, 0, 0, 0, ZoneOffset.UTC);
    private static final int COOLDOWN = 60;

    @Test
    void firesWhenBreachedAndNotAlerting() {
        assertThat(QueueDepthAlertService.evaluate(1000, 1000, false, null, NOW, COOLDOWN))
                .isEqualTo(AlertDecision.FIRE);
    }

    @Test
    void valueBelowThresholdDoesNotFire() {
        assertThat(QueueDepthAlertService.evaluate(999, 1000, false, null, NOW, COOLDOWN))
                .isEqualTo(AlertDecision.NONE);
    }

    @Test
    void suppressesRepeatAlertWithinCooldown() {
        OffsetDateTime lastAlerted = NOW.minusMinutes(30); // inside the 60-min cooldown
        assertThat(QueueDepthAlertService.evaluate(5000, 1000, true, lastAlerted, NOW, COOLDOWN))
                .isEqualTo(AlertDecision.NONE);
    }

    @Test
    void reAlertsAfterCooldownElapsed() {
        OffsetDateTime lastAlerted = NOW.minusMinutes(61); // past the 60-min cooldown
        assertThat(QueueDepthAlertService.evaluate(5000, 1000, true, lastAlerted, NOW, COOLDOWN))
                .isEqualTo(AlertDecision.FIRE);
    }

    @Test
    void reAlertsAtExactCooldownBoundary() {
        // Exactly cooldown ago → not strictly after the cutoff → re-alert.
        assertThat(QueueDepthAlertService.evaluate(5000, 1000, true, NOW.minusMinutes(60), NOW, COOLDOWN))
                .isEqualTo(AlertDecision.FIRE);
    }

    @Test
    void firesWhenAlertingButNoLastAlertedTimestamp() {
        assertThat(QueueDepthAlertService.evaluate(5000, 1000, true, null, NOW, COOLDOWN))
                .isEqualTo(AlertDecision.FIRE);
    }

    @Test
    void recoversWhenBackBelowThresholdWhileAlerting() {
        assertThat(QueueDepthAlertService.evaluate(0, 1000, true, NOW.minusMinutes(5), NOW, COOLDOWN))
                .isEqualTo(AlertDecision.RECOVER);
    }

    @Test
    void steadyHealthyStateIsNoOp() {
        assertThat(QueueDepthAlertService.evaluate(0, 1000, false, null, NOW, COOLDOWN))
                .isEqualTo(AlertDecision.NONE);
    }

    @Test
    void dlqAlertsOnFirstDeadLetter() {
        // DLQ threshold of 1 — a single dead-lettered message must fire.
        assertThat(QueueDepthAlertService.evaluate(1, 1, false, null, NOW, COOLDOWN))
                .isEqualTo(AlertDecision.FIRE);
    }

    @Test
    void disabledThresholdNeverBreaches() {
        assertThat(QueueDepthAlertService.evaluate(10_000, 0, false, null, NOW, COOLDOWN))
                .isEqualTo(AlertDecision.NONE);
    }

    @Test
    void scheduledRun_deniedByTheJobPolicy_touchesNothing() {
        SchedulerExecutionPolicy policy = org.mockito.Mockito.mock(SchedulerExecutionPolicy.class);
        com.certmanagement.messaging.transport.PostgresMessageQueue queue =
                org.mockito.Mockito.mock(com.certmanagement.messaging.transport.PostgresMessageQueue.class);
        com.certmanagement.config.QueueAlertProperties props =
                org.mockito.Mockito.mock(com.certmanagement.config.QueueAlertProperties.class);
        org.mockito.Mockito.when(policy.canRun("queue-alert")).thenReturn(false);
        QueueDepthAlertService service = new QueueDepthAlertService(queue, policy, props,
                org.mockito.Mockito.mock(com.certmanagement.repository.QueueAlertStateRepository.class),
                org.mockito.Mockito.mock(com.certmanagement.messaging.OperationalAlertPublisher.class));

        service.runQueueDepthChecks();

        org.mockito.Mockito.verifyNoInteractions(queue, props);
    }

    @Test
    void scheduledRun_readsChannelDepthFromTheQueue_andFiresOnBreach() {
        SchedulerExecutionPolicy policy = org.mockito.Mockito.mock(SchedulerExecutionPolicy.class);
        com.certmanagement.messaging.transport.PostgresMessageQueue queue =
                org.mockito.Mockito.mock(com.certmanagement.messaging.transport.PostgresMessageQueue.class);
        com.certmanagement.repository.QueueAlertStateRepository stateRepo =
                org.mockito.Mockito.mock(com.certmanagement.repository.QueueAlertStateRepository.class);
        com.certmanagement.messaging.OperationalAlertPublisher publisher =
                org.mockito.Mockito.mock(com.certmanagement.messaging.OperationalAlertPublisher.class);
        com.certmanagement.config.QueueAlertProperties props = new com.certmanagement.config.QueueAlertProperties();
        com.certmanagement.config.QueueAlertProperties.Entity entity = new com.certmanagement.config.QueueAlertProperties.Entity();
        entity.setName("cert-agent-outbound");
        entity.setActiveThreshold(5L);
        entity.setDlqThreshold(1L);
        props.getEntities().add(entity);
        org.mockito.Mockito.when(policy.canRun("queue-alert")).thenReturn(true);
        java.util.Map<String, Long> depth = new java.util.LinkedHashMap<>();
        depth.put("READY", 3L);
        depth.put("LEASED", 2L);
        depth.put("DEAD", 1L);
        org.mockito.Mockito.when(queue.depth("cert-agent-outbound")).thenReturn(depth);
        org.mockito.Mockito.when(stateRepo.findByEntityNameAndMetric(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(java.util.Optional.empty());
        org.mockito.Mockito.when(stateRepo.claimFire(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any())).thenReturn(1);

        new QueueDepthAlertService(queue, policy, props, stateRepo, publisher).runQueueDepthChecks();

        // ACTIVE counts ready plus locked messages; DLQ counts dead-lettered ones.
        org.mockito.Mockito.verify(publisher).publishQueueAlert("SYSTEM_QUEUE_DEPTH_WARNING",
                "cert-agent-outbound", "QUEUE", "ACTIVE", 5L, 5L, "WARNING");
        org.mockito.Mockito.verify(publisher).publishQueueAlert("SYSTEM_DLQ_ALERT",
                "cert-agent-outbound", "QUEUE", "DLQ", 1L, 1L, "CRITICAL");
    }
}
