// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.cahealth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
@Table(name = "iot_ca_health_status")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotCaHealthStatus {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "organization_id", nullable = false)
    private Long organizationId;
    @Column(name = "connector_id", nullable = false, length = 100)
    private String connectorId;
    @Column(name = "ca_provider", nullable = false, length = 50)
    private String caProvider;
    @Column(nullable = false)
    private Boolean enabled;
    @Column(name = "health_status", nullable = false, length = 30)
    private String healthStatus;
    @Column(name = "checked_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime checkedAt;
    @Column(name = "responded_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime respondedAt;
    @Column(name = "received_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime receivedAt;
    @Column(name = "latency_ms")
    private Long latencyMs;
    @Column(length = 1000)
    private String endpoint;
    @Column(name = "auth_method", length = 80)
    private String authMethod;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "product_json", columnDefinition = "jsonb")
    private String productJson;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "capabilities_json", nullable = false, columnDefinition = "jsonb")
    private String capabilitiesJson;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "profiles_json", nullable = false, columnDefinition = "jsonb")
    private String profilesJson;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "issues_json", nullable = false, columnDefinition = "jsonb")
    private String issuesJson;
    @Column(name = "report_version", nullable = false)
    private Integer reportVersion;
    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
