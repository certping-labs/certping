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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLRestriction;

import java.time.OffsetDateTime;

@Entity
@Table(name = "discovery_config")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DiscoveryConfigEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "target_type", nullable = false, length = 50)
    private String targetType;

    @Column(name = "credential_xref", nullable = false, length = 100)
    private String credentialXref;

    @Column(name = "credential_updated_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime credentialUpdatedAt;

    @Column(name = "scope_key", length = 64)
    private String scopeKey;

    @Column(name = "last_request_id", length = 100)
    private String lastRequestId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    @Builder.Default
    private DiscoveryConfigStatus status = DiscoveryConfigStatus.READY;

    @Column(name = "status_message", nullable = false, length = 300)
    @Builder.Default
    private String statusMessage = "Discovery is ready to run.";

    @Column(name = "last_started_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastStartedAt;

    @Column(name = "last_completed_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastCompletedAt;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        updatedAt = now;
        if (isDeleted == null) {
            isDeleted = false;
        }
        if (status == null) {
            status = DiscoveryConfigStatus.READY;
        }
        if (statusMessage == null || statusMessage.isBlank()) {
            statusMessage = "Discovery is ready to run.";
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
