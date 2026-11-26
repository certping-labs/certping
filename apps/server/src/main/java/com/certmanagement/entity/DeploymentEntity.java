// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.Map;

@Entity
@Table(name = "deployments")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeploymentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable = false, unique = true, length = 100)
    private String requestId;

    @Column(name = "correlation_id", length = 100)
    private String correlationId;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "certificate_xref", nullable = false, length = 100)
    private String certificateXref;

    @Column(name = "user_domain_cert_id")
    private Long userDomainCertId;

    @Column(name = "deployment_credential_xref", length = 100)
    private String deploymentCredentialXref;

    @Column(name = "target_type", nullable = false, length = 50)
    private String targetType;

    @Column(name = "flow_type", nullable = false, length = 50)
    private String flowType;

    @Column(name = "status", nullable = false, length = 50)
    private String status;

    @Column(name = "cert_secret_handle", length = 500)
    private String certSecretHandle;

    @Column(name = "deployment_cred_handle", length = 500)
    private String deploymentCredHandle;

    @Column(name = "target_resource_id", length = 1000)
    private String targetResourceId;

    @Column(name = "error_code", length = 100)
    private String errorCode;

    @Column(name = "error_detail", columnDefinition = "TEXT")
    private String errorDetail;

    @Column(name = "requested_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime requestedAt;

    @Column(name = "published_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime publishedAt;

    @Column(name = "responded_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime respondedAt;

    @Column(name = "completed_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime completedAt;

    @Column(name = "source", length = 100)
    private String source;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata", columnDefinition = "jsonb")
    private Map<String, Object> metadata;

    @Column(name = "created_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @Column(name = "is_deleted", nullable = false)
    private boolean isDeleted;

    @PrePersist
    protected void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        if (requestedAt == null) {
            requestedAt = now;
        }
        isDeleted = false;
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
