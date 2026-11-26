// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

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
import jakarta.persistence.Version;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Entity
@Table(name = "iot_certificate_profile")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateProfile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "profile_xref", nullable = false, length = 100)
    private String profileXref;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;

    @Column(nullable = false, length = 200)
    private String name;

    @Column(length = 1000)
    private String description;

    @Column(name = "target_platform", nullable = false, length = 80)
    private String targetPlatform;

    @Column(name = "target_variant", nullable = false, length = 80)
    private String targetVariant;

    @Column(name = "provider_profile_type", nullable = false, length = 150)
    private String providerProfileType;

    @Column(name = "provider_profile_id", length = 500)
    private String providerProfileId;

    @Column(name = "provider_correlation_marker", length = 200)
    private String providerCorrelationMarker;

    @Enumerated(EnumType.STRING)
    @Column(name = "lifecycle_status", nullable = false, length = 30)
    private ProfileLifecycleStatus lifecycleStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "profile_origin", nullable = false, length = 30)
    private ProfileOrigin profileOrigin;

    @Enumerated(EnumType.STRING)
    @Column(name = "control_mode", nullable = false, length = 30)
    private ProfileControlMode controlMode;

    @Enumerated(EnumType.STRING)
    @Column(name = "profile_kind", nullable = false, length = 50)
    private ProfileKind profileKind;

    @Column(name = "enrollment_method", length = 50)
    private String enrollmentMethod;

    @Column(name = "desired_revision")
    private Long desiredRevision;

    @Column(name = "applied_revision")
    private Long appliedRevision;

    @Column(name = "latest_operation_xref", length = 100)
    private String latestOperationXref;

    @Column(name = "latest_operation_started_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime latestOperationStartedAt;

    @Column(name = "latest_operation_completed_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime latestOperationCompletedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider_sync_status", nullable = false, length = 30)
    private ProviderSyncStatus providerSyncStatus;

    @Column(name = "provider_sync_error", length = 1000)
    private String providerSyncError;

    @Column(name = "last_provider_synced_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastProviderSyncedAt;

    @Column(name = "last_provider_sync_xref", length = 100)
    private String lastProviderSyncXref;

    @Column(name = "created_by_user_id")
    private Long createdByUserId;

    @Column(name = "updated_by_user_id")
    private Long updatedByUserId;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @Version
    @Column(name = "row_version", nullable = false)
    private Long rowVersion;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        updatedAt = now;
        if (targetVariant == null) {
            targetVariant = "STANDARD";
        }
        if (providerSyncStatus == null) {
            providerSyncStatus = ProviderSyncStatus.NEVER;
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
