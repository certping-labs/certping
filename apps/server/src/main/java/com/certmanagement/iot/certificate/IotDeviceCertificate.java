// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

@Entity
@DynamicUpdate
@Table(name = "iot_device_certificate")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceCertificate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "certificate_xref", nullable = false, length = 100)
    private String certificateXref;
    @Column(name = "enrollment_id", nullable = false)
    private Long enrollmentId;
    @Column(name = "organization_id", nullable = false)
    private Long organizationId;
    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;
    /** Optional: null until the exact Intune certificate profile is proven for the enrollment. */
    @Column(name = "profile_id")
    private Long profileId;
    @Column(name = "device_id")
    private Long deviceId;
    @Column(name = "ca_provider", nullable = false, length = 50)
    private String caProvider;
    @Column(name = "issuer_xref", length = 100)
    private String issuerXref;
    @Column(name = "ca_name", length = 255)
    private String caName;
    @Column(name = "ca_end_entity_name", length = 255)
    private String caEndEntityName;
    @Column(name = "ca_provisioner_name", length = 255)
    private String caProvisionerName;
    @Column(name = "issuer_dn", nullable = false, length = 2000)
    private String issuerDn;
    @Column(name = "serial_number", nullable = false, length = 160)
    private String serialNumber;
    @Column(name = "subject_dn", nullable = false, length = 2000)
    private String subjectDn;
    @Column(name = "common_name", length = 500)
    private String commonName;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "subject_alt_names_json", nullable = false, columnDefinition = "jsonb")
    private String subjectAltNamesJson;
    @Column(name = "certificate_scope", length = 20)
    private String certificateScope;
    /** Exact key used by Intune managed-device certificate-state reports. */
    @Column(name = "fingerprint_sha1", nullable = false, length = 40)
    private String fingerprintSha1;
    @Column(name = "fingerprint_sha256", nullable = false, length = 64)
    private String fingerprintSha256;
    @Column(name = "valid_from", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime validFrom;
    @Column(name = "valid_to", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime validTo;
    @Column(name = "signature_algorithm", length = 100)
    private String signatureAlgorithm;
    @Column(name = "signature_algorithm_oid", length = 100)
    private String signatureAlgorithmOid;
    @Column(name = "public_key_algorithm", length = 30)
    private String publicKeyAlgorithm;
    @Column(name = "key_size")
    private Integer keySize;
    @Column(name = "public_key_curve", length = 100)
    private String publicKeyCurve;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "key_usage_json", nullable = false, columnDefinition = "jsonb")
    private String keyUsageJson;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "extended_key_usage_oids_json", nullable = false, columnDefinition = "jsonb")
    private String extendedKeyUsageOidsJson;
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "certificate_policy_oids_json", nullable = false, columnDefinition = "jsonb")
    private String certificatePolicyOidsJson;
    @Column(name = "subject_key_identifier", length = 255)
    private String subjectKeyIdentifier;
    @Column(name = "authority_key_identifier", length = 255)
    private String authorityKeyIdentifier;
    @Column(name = "is_ca", nullable = false)
    private Boolean certificateAuthority;
    @Column(nullable = false, length = 40)
    private String status;
    @Column(name = "issued_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime issuedAt;
    /** Observed renewal lifecycle: NONE, NUDGING, or RENEWED. */
    @Column(name = "renewal_state", nullable = false, length = 20)
    private String renewalState;
    @Column(name = "nudge_attempts", nullable = false)
    private Integer nudgeAttempts;
    @Column(name = "last_nudged_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastNudgedAt;
    @Column(name = "last_nudge_request_id", length = 100)
    private String lastNudgeRequestId;
    @Column(name = "last_nudge_outcome", length = 40)
    private String lastNudgeOutcome;
    @Column(name = "renewal_due_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime renewalDueAt;
    @Column(name = "created_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;
    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
