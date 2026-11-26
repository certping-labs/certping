// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

/** Append-only audit trail. Only write when something actually changed. */
@Entity
@Table(name = "iot_device_event")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_xref", nullable = false, length = 100)
    private String eventXref;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "device_id")
    private Long deviceId;

    @Column(name = "certificate_enrollment_id")
    private Long certificateEnrollmentId;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private DeviceEventType eventType;

    @Column(name = "event_status", nullable = false, length = 50)
    private String eventStatus;

    @Column(name = "event_message", length = 1000)
    private String eventMessage;

    @Column(name = "actor_user_id")
    private Long actorUserId;

    @Enumerated(EnumType.STRING)
    @Column(name = "actor_source", length = 50)
    private ActorSource actorSource;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "detail_json", columnDefinition = "jsonb")
    private String detailJson;

    @Column(name = "occurred_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime occurredAt;

    @Column(name = "received_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime receivedAt;

    @Column(name = "correlation_id", length = 100)
    private String correlationId;

    @Column(name = "dedupe_key", length = 255)
    private String dedupeKey;

    @PrePersist
    void onCreate() {
        if (occurredAt == null) {
            occurredAt = OffsetDateTime.now();
        }
        if (receivedAt == null) {
            receivedAt = OffsetDateTime.now();
        }
    }
}
