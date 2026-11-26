// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Entity
@Table(
        name = "discovered_cert_observation",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_discovered_cert_observation_scope",
                columnNames = {"discovered_cert_id", "scope_key"}))
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DiscoveredCertObservationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "discovered_cert_id", nullable = false)
    private Long discoveredCertId;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "target_type", nullable = false, length = 50)
    private String targetType;

    @Column(name = "credential_xref", nullable = false, length = 255)
    private String credentialXref;

    @Column(name = "scope_key", nullable = false, length = 64)
    private String scopeKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private DiscoveryObservationStatus status;

    @Column(name = "last_seen_request_id", nullable = false, length = 100)
    private String lastSeenRequestId;

    @Column(name = "first_seen_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime firstSeenAt;

    @Column(name = "last_seen_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastSeenAt;

    @Column(name = "missing_since", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime missingSince;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
