// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import com.certmanagement.iot.enums.DeviceSourceEventType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

@Entity
@Table(name = "iot_device_source_event")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceSourceEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_xref", nullable = false, length = 100)
    private String eventXref;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private DeviceSourceEventType eventType;

    @Column(name = "event_status", length = 50)
    private String eventStatus;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "detail_json", columnDefinition = "jsonb")
    private String detailJson;

    @Column(name = "occurred_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime occurredAt;

    @Column(name = "received_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime receivedAt;

    @Column(name = "correlation_id", length = 100)
    private String correlationId;

    @Column(name = "dedupe_key", nullable = false, length = 200)
    private String dedupeKey;
}
