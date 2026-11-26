// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.model;

import com.certping.notification.enums.IntegrationType;
import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Entity
@Table(name = "notification_records")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;

    @Column(name = "organization_id")
    private Long organizationId;

    private String websiteId;

    private String email;
    private String templateName;
    private String subject;
    private String sentBy;

    @Enumerated(EnumType.STRING)
    private IntegrationType integrationType;

    @Enumerated(EnumType.STRING)
    private NotificationStatus status;

    @Column(length = 4000)
    private String payloadJson;

    @Column(length = 1000)
    private String failureReason;

    private OffsetDateTime sentAt;
    private OffsetDateTime createdAt;
    private OffsetDateTime updatedAt;

    /** Publisher-supplied stable identity. Used as the natural key for
     *  find-or-insert so that a scheduled retry updates the same row instead
     *  of creating a new one per attempt. Unique index enforced at the
     *  application level via findByRequestId + the Postgres partial unique
     *  index on request_id in the server's schema. */
    @Column(name = "request_id")
    private String requestId;

    @Column(name = "correlation_id")
    private String correlationId;

    @PrePersist
    protected void onCreate() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
    }
}
