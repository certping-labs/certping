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
@Table(name = "iot_certificate_profile_configuration")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateProfileConfiguration {
    @Id
    @Column(name = "profile_id")
    private Long profileId;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;

    @Column(name = "issuer_xref", length = 100)
    private String issuerXref;

    @Column(name = "certificate_scope", length = 20)
    private String certificateScope;

    @Column(name = "key_algorithm", length = 20)
    private String keyAlgorithm;

    @Column(name = "key_size")
    private Integer keySize;

    @Column(length = 50)
    private String curve;

    @Column(name = "signature_hash", length = 30)
    private String signatureHash;

    @Column(name = "subject_name_format", length = 1000)
    private String subjectNameFormat;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "subject_alt_name_formats_json", nullable = false, columnDefinition = "jsonb")
    private String subjectAltNameFormatsJson;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "extended_key_usages_json", nullable = false, columnDefinition = "jsonb")
    private String extendedKeyUsagesJson;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "key_usages_json", nullable = false, columnDefinition = "jsonb")
    private String keyUsagesJson;

    @Column(name = "validity_value")
    private Integer validityValue;

    @Column(name = "validity_unit", length = 20)
    private String validityUnit;

    @Column(name = "renewal_window_days")
    private Integer renewalWindowDays;

    @Column(name = "key_exportable")
    private Boolean keyExportable;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "provider_config_json", nullable = false, columnDefinition = "jsonb")
    private String providerConfigJson;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
