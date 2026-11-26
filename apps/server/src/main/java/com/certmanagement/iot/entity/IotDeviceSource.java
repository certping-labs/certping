// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

@Entity
@Table(name = "iot_device_source")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceSource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "source_xref", nullable = false, length = 100)
    private String sourceXref;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 50)
    private DeviceSourceProvider provider;

    @Enumerated(EnumType.STRING)
    @Column(name = "source_category", nullable = false, length = 50)
    private DeviceSourceCategory sourceCategory;

    @Column(name = "connection_profile_ref", nullable = false, length = 100)
    private String connectionProfileRef;

    @Column(name = "display_name", nullable = false, length = 200)
    private String displayName;

    @Column(name = "description", length = 500)
    private String description;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "configuration_metadata_json", columnDefinition = "jsonb")
    private String configurationMetadataJson;

    @Column(name = "sync_enabled", nullable = false)
    @Builder.Default
    private Boolean syncEnabled = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    @Builder.Default
    private DeviceSourceStatus status = DeviceSourceStatus.ACTIVE;

    @Column(name = "first_advertised_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime firstAdvertisedAt;

    @Column(name = "last_advertised_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastAdvertisedAt;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        updatedAt = now;
        syncEnabled = Boolean.TRUE.equals(syncEnabled);
        if (status == null) {
            status = DeviceSourceStatus.ACTIVE;
        }
        if (firstAdvertisedAt == null) {
            firstAdvertisedAt = now;
        }
        if (lastAdvertisedAt == null) {
            lastAdvertisedAt = firstAdvertisedAt;
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
