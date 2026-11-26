// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

@Entity
@Table(name = "discovery_scan")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DiscoveryScanEntity {

    @Id
    @Column(name = "request_id", length = 100)
    private String requestId;

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
    private DiscoveryScanStatus status;

    @Column(name = "expected_batches")
    private Integer expectedBatches;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "received_batch_indices", nullable = false, columnDefinition = "integer[]")
    private Integer[] receivedBatchIndices;

    @Column(name = "received_cert_count", nullable = false)
    private int receivedCertCount;

    @Column(name = "completion_received", nullable = false)
    private boolean completionReceived;

    @Column(name = "reported_total_certs")
    private Integer reportedTotalCerts;

    /**
     * The scopes the agent could not read, as JSON (FailedScopes); null when it read everything. A
     * scan that finalizes with any ends PARTIAL, and their certificates are not marked MISSING.
     */
    @Column(name = "failed_scopes", columnDefinition = "TEXT")
    private String failedScopes;

    @Column(name = "requested_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime requestedAt;

    @Column(name = "completed_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime completedAt;

    @Column(name = "finalized_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime finalizedAt;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        updatedAt = now;
        if (receivedBatchIndices == null) {
            receivedBatchIndices = new Integer[0];
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
