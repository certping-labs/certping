// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

/**
 * Append-only audit trail for every certificate state change and operation.
 * No UPDATE or DELETE ever issued — INSERT only.
 */
@Entity
@Table(name = "certificate_events")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "certificate_xref", nullable = false, length = 100)
    private String certificateXref;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    /** Stored as {@link com.certmanagement.enums.CertEventType#name()}. */
    @Column(name = "event_type", nullable = false, length = 100)
    private String eventType;

    @Column(name = "from_status", length = 50)
    private String fromStatus;

    @Column(name = "to_status", length = 50)
    private String toStatus;

    @Column(name = "request_id", length = 100)
    private String requestId;

    @Column(name = "correlation_id", length = 100)
    private String correlationId;

    @Column(name = "user_id")
    private Integer userId;

    @Column(name = "reason", length = 50)
    private String reason;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "details", columnDefinition = "jsonb")
    private String details;

    /** Stored as {@link com.certmanagement.enums.EventSource#value()}. */
    @Column(name = "source", length = 100)
    private String source;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "occurred_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime occurredAt;

    @PrePersist
    protected void onCreate() {
        occurredAt = OffsetDateTime.now();
        if (isDeleted == null) {
            isDeleted = false;
        }
    }
}
