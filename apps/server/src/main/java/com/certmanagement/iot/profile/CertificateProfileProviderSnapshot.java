// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
@Table(name = "iot_certificate_profile_provider_snapshot")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateProfileProviderSnapshot {
    @Id
    @Column(name = "profile_id")
    private Long profileId;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "provider_response_json", nullable = false, columnDefinition = "jsonb")
    private String providerResponseJson;

    @Column(name = "response_schema_version", nullable = false)
    private Integer responseSchemaVersion;

    @Column(name = "provider_version", length = 100)
    private String providerVersion;

    @Column(name = "provider_last_modified_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime providerLastModifiedAt;

    @Column(name = "provider_observed_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime providerObservedAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
