// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import com.certmanagement.enums.AgentDeepHealthMetricStatus;
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

import java.time.OffsetDateTime;

@Entity
@Table(name = "agent_deep_health_check_metrics")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AgentDeepHealthCheckMetricEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "deep_check_id", nullable = false, length = 100)
    private String deepCheckId;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "chunk_index", nullable = false)
    private Integer chunkIndex;

    @Column(name = "metric_key", nullable = false, length = 256)
    private String metricKey;

    @Column(name = "metric_name", nullable = false, length = 128)
    private String metricName;

    @Column(name = "metric_group", nullable = false, length = 64)
    private String metricGroup;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private AgentDeepHealthMetricStatus status;

    @Column(name = "path", length = 1000)
    private String path;

    @Column(name = "message", columnDefinition = "TEXT")
    private String message;

    @Column(name = "details", columnDefinition = "TEXT")
    private String details;

    @Column(name = "responded_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime respondedAt;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = OffsetDateTime.now();
    }
}
