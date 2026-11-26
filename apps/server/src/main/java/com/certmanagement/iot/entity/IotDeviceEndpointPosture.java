// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import com.certmanagement.iot.enums.ComplianceState;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

/** MDM posture facet — Intune, Jamf, Workspace ONE. */
@Entity
@Table(name = "iot_device_endpoint_posture")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceEndpointPosture {

    @Id
    @Column(name = "device_id")
    private Long deviceId;

    @Column(name = "operating_system", length = 50)
    private String operatingSystem;

    @Column(name = "os_version", length = 100)
    private String osVersion;

    @Enumerated(EnumType.STRING)
    @Column(name = "compliance_state", length = 30)
    private ComplianceState complianceState;

    @Column(name = "compliance_state_raw", length = 100)
    private String complianceStateRaw;

    @Column(name = "is_encrypted")
    private Boolean isEncrypted;

    @Column(name = "is_supervised")
    private Boolean isSupervised;

    @Column(name = "jailbroken_state", length = 20)
    private String jailbrokenState;

    @Column(name = "management_agent", length = 50)
    private String managementAgent;

    @Column(name = "enrollment_type", length = 100)
    private String enrollmentType;

    @Column(name = "mdm_enrolled_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime mdmEnrolledAt;

    @Column(name = "mdm_last_sync_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime mdmLastSyncAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "vendor_attributes", columnDefinition = "jsonb")
    private String vendorAttributes;
}
