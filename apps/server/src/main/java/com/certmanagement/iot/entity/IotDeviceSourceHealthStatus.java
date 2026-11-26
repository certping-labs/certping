// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import com.certmanagement.iot.enums.DeviceSourceHealth;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
@Table(name = "iot_device_source_health_status")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceSourceHealthStatus {
    @Id
    @Column(name = "device_source_id")
    private Long deviceSourceId;

    @Column(name = "last_health_xref", nullable = false, length = 100)
    private String lastHealthXref;

    @Enumerated(EnumType.STRING)
    @Column(name = "health_status", nullable = false, length = 30)
    private DeviceSourceHealth healthStatus;

    @Column(name = "provider_status", length = 100)
    private String providerStatus;

    @Column(name = "status_message", length = 1000)
    private String statusMessage;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "health_metadata_json", columnDefinition = "jsonb")
    private String healthMetadataJson;

    @Column(name = "agent_instance_xref", nullable = false, length = 100)
    private String agentInstanceXref;

    @Column(name = "agent_sequence", nullable = false)
    private Long agentSequence;

    @Column(name = "check_started_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime checkStartedAt;

    @Column(name = "observed_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime observedAt;

    @Column(name = "published_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime publishedAt;

    @Column(name = "received_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime receivedAt;

    @Column(name = "response_time_ms")
    private Long responseTimeMs;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
