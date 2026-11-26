// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import com.certmanagement.enums.AlertSeverity;
import com.certmanagement.enums.AlertStatus;
import com.certmanagement.enums.AlertTypeEnum;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLRestriction;

import java.time.Instant;

/**
 * Represents an in-app alert row in the {@code alert} table.
 *
 * <p>Ownership is exclusive: a row belongs to either an organization or a user,
 * enforced by the DB constraint {@code chk_alert_exclusive_owner}:
 * {@code (user_id IS NOT NULL AND organization_id IS NULL) OR (user_id IS NULL AND organization_id IS NOT NULL)}.
 *
 * <p>Alerts are written by {@link com.certmanagement.messaging.CertResponseProcessor}
 * on FAILED / AGENT_ERROR events and are readable via {@link com.certmanagement.controller.AlertController}.
 */
@Entity
@Table(name = "alert")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Metadata only — not used for lookups. */
    @Column(name = "user_email", length = 255)
    private String userEmail;

    /** User ownership, mutually exclusive with organizationId. */
    @Column(name = "user_id")
    private Integer userId;

    /** Organization ownership — mutually exclusive with userId. */
    @Column(name = "organization_id")
    private Long organizationId;

    @Enumerated(EnumType.STRING)
    @Column(name = "alert_type", length = 50)
    private AlertTypeEnum alertType;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 50)
    private AlertStatus status;

    @Column(name = "message", columnDefinition = "TEXT")
    private String message;

    @Column(name = "error_detail", columnDefinition = "TEXT")
    private String errorDetail;

    @Column(name = "error_code", length = 100)
    private String errorCode;

    /**
     * Per-operation trace id of the failure that produced this alert. Surfaced to the user as a
     * support "Reference ID"; never carries system detail. Null for non-correlated alert sources.
     */
    @Column(name = "correlation_id", length = 100)
    private String correlationId;

    @Column(name = "domain", length = 255)
    private String domain;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "created_at", columnDefinition = "TIMESTAMPTZ")
    private Instant createdAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", length = 20)
    private AlertSeverity severity;

    @Column(name = "unread", nullable = false)
    @Builder.Default
    private Boolean unread = true;

    @PrePersist
    protected void prePersistDefaults() {
        if (createdAt == null) createdAt = Instant.now();
        if (severity   == null) severity  = AlertSeverity.CRITICAL;
        if (unread     == null) unread    = true;
        if (isDeleted  == null) isDeleted = false;
    }
}
