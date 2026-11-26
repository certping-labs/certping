// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

/**
 * Durable alert state for one {@code (entity_name, metric)} pair watched by
 * {@link com.certmanagement.service.scheduler.QueueDepthAlertService}.
 *
 * <p>The server may run multiple replicas with no leader election, so the row is also the
 * cross-replica lock: the service never mutates this entity through JPA dirty-checking — it drives
 * every transition through the atomic conditional UPDATEs on
 * {@link com.certmanagement.repository.QueueAlertStateRepository} so exactly one replica wins the
 * right to send each email. This entity exists for the {@code @Query} host, lazy row creation, and
 * read-back in tests.
 */
@Entity
@Table(name = "queue_alert_state")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class QueueAlertStateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Watched entity key: a message queue channel name. */
    @Column(name = "entity_name", nullable = false, length = 512)
    private String entityName;

    /** {@code ACTIVE} (backlog) or {@code DLQ} (dead-letter depth). */
    @Column(name = "metric", nullable = false, length = 16)
    private String metric;

    /** {@code OK} or {@code ALERTING}. */
    @Column(name = "alert_state", nullable = false, length = 16)
    @Builder.Default
    private String alertState = "OK";

    @Column(name = "last_value", nullable = false)
    @Builder.Default
    private Long lastValue = 0L;

    /** Reserved for future sustained-N-polls gating; v1 alerts on the first breach. */
    @Column(name = "consecutive_breaches", nullable = false)
    @Builder.Default
    private Integer consecutiveBreaches = 0;

    @Column(name = "last_alerted_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastAlertedAt;

    @Column(name = "recovered_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime recoveredAt;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = OffsetDateTime.now();
        updatedAt = createdAt;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
