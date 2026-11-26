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
import java.time.OffsetDateTime;

@Entity
@DynamicUpdate
@Table(name = "iot_certificate_enrollment")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotCertificateEnrollment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "enrollment_xref", nullable = false, length = 100)
    private String enrollmentXref;
    @Column(name = "organization_id", nullable = false)
    private Long organizationId;
    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;
    /** Optional: null until the exact Intune certificate profile is proven (see profileResolutionStatus). */
    @Column(name = "profile_id")
    private Long profileId;
    @Column(name = "device_id")
    private Long deviceId;
    /** The SCEP route key the device called — the source connectionProfileRef, never a profileXref. */
    @Column(name = "endpoint_id", nullable = false, length = 100)
    private String endpointId;
    @Column(name = "transaction_id", nullable = false, length = 255)
    private String transactionId;
    @Column(name = "csr_fingerprint_sha256", length = 64)
    private String csrFingerprintSha256;
    @Column(name = "asserted_source_device_id", length = 500)
    private String assertedSourceDeviceId;
    /** Claimed namespace of the identifier: MANAGED_DEVICE_ID, ENTRA_DEVICE_ID, ENTRA_OBJECT_ID, UNKNOWN. */
    @Column(name = "source_identifier_type", length = 30)
    private String sourceIdentifierType;
    /** MICROSOFT_VALIDATED or ASSERTED — only the former may ever auto-link a device. */
    @Column(name = "source_identifier_assurance", length = 30)
    private String sourceIdentifierAssurance;
    /** MATCHED, PENDING_SYNC, NOT_FOUND, or AMBIGUOUS. */
    @Column(name = "profile_resolution_status", nullable = false, length = 20)
    private String profileResolutionStatus;
    @Column(name = "enrollment_type", nullable = false, length = 20)
    private String enrollmentType;
    @Column(name = "prior_certificate_issuer_dn", length = 2000)
    private String priorCertificateIssuerDn;
    @Column(name = "prior_certificate_serial_number", length = 160)
    private String priorCertificateSerialNumber;
    @Column(name = "device_match_status", nullable = false, length = 30)
    private String deviceMatchStatus;
    @Column(nullable = false, length = 40)
    private String status;
    @Column(name = "failure_stage", length = 50)
    private String failureStage;
    @Column(name = "error_code", length = 100)
    private String errorCode;
    @Column(name = "error_message", length = 1000)
    private String errorMessage;
    @Column(nullable = false)
    private Boolean retryable;
    @Column(name = "requested_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime requestedAt;
    @Column(name = "validated_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime validatedAt;
    @Column(name = "issued_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime issuedAt;
    @Column(name = "completed_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime completedAt;
    @Column(name = "created_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;
    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
