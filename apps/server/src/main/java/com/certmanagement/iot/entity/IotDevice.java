// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import com.certmanagement.iot.enums.DeviceClass;
import com.certmanagement.iot.enums.DeviceOwnership;
import com.certmanagement.iot.enums.DeviceStatus;
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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

/**
 * One provider device under one configured source. A physical device present in two sources has
 * two rows in this first version. Cross-source reconciliation can be added later without making
 * discovery ambiguous today.
 */
@Entity
@Table(name = "iot_device")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDevice {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "device_xref", nullable = false, length = 100)
    private String deviceXref;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;

    @Column(name = "source_device_id", nullable = false, length = 500)
    private String sourceDeviceId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "source_identifiers_json", columnDefinition = "jsonb")
    private String sourceIdentifiersJson;

    @Enumerated(EnumType.STRING)
    @Column(name = "device_class", nullable = false, length = 30)
    private DeviceClass deviceClass;

    @Column(name = "serial_number", length = 255)
    private String serialNumber;

    @Column(name = "device_name", length = 255)
    private String deviceName;

    @Column(name = "manufacturer", length = 200)
    private String manufacturer;

    @Column(name = "model", length = 200)
    private String model;

    /** COMPANY vs PERSONAL describes the device, not a person — not PII. */
    @Enumerated(EnumType.STRING)
    @Column(name = "ownership", length = 30)
    private DeviceOwnership ownership;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    @Builder.Default
    private DeviceStatus status = DeviceStatus.REGISTERED;

    @Column(name = "registered_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime registeredAt;

    @Column(name = "last_seen_in_source_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastSeenInSourceAt;

    @Column(name = "decommissioned_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime decommissionedAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "provider_attributes_json", columnDefinition = "jsonb")
    private String providerAttributesJson;

    @Column(name = "provider_attributes_schema_version", nullable = false)
    @Builder.Default
    private Integer providerAttributesSchemaVersion = 1;

    @Column(name = "provider_attributes_updated_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime providerAttributesUpdatedAt;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    // Left null until insert: a non-null version makes Spring Data merge a new device into a copy,
    // leaving the caller's instance without an ID.
    @Version
    @Column(name = "row_version", nullable = false)
    private Long rowVersion;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        updatedAt = now;
        if (isDeleted == null) {
            isDeleted = false;
        }
        if (status == null) {
            status = DeviceStatus.REGISTERED;
        }
        if (providerAttributesSchemaVersion == null) {
            providerAttributesSchemaVersion = 1;
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
