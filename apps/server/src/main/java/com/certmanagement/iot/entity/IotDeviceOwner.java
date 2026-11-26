// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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

/** Owner PII, isolated and empty by default. Soft-deletes independently of the device. */
@Entity
@Table(name = "iot_device_owner")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceOwner {

    @Id
    @Column(name = "device_id")
    private Long deviceId;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "owner_upn", length = 320)
    private String ownerUpn;

    @Column(name = "owner_email", length = 320)
    private String ownerEmail;

    @Column(name = "owner_display_name", length = 255)
    private String ownerDisplayName;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    @PreUpdate
    void touch() {
        updatedAt = OffsetDateTime.now();
        if (isDeleted == null) {
            isDeleted = false;
        }
    }
}
