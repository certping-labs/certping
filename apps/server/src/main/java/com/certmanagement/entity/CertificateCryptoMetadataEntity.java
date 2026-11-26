// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import com.certmanagement.service.cbom.CertificateInventoryEntityListener;
import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

/**
 * Stores extended X.509 cryptographic metadata extracted by the agent at issuance/renewal time.
 * Kept in a separate table to avoid bloating the certificates table.
 * Used by CbomProjectionService and future PQC readiness scoring.
 *
 * One row per certificate_xref — upserted on each issuance/renewal response.
 */
@Entity
@Table(name = "certificate_crypto_metadata")
@EntityListeners(CertificateInventoryEntityListener.class)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateCryptoMetadataEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "certificate_xref", nullable = false, unique = true, length = 100)
    private String certificateXref;

    @Column(name = "signature_algorithm_oid", length = 100)
    private String signatureAlgorithmOid;

    @Column(name = "subject_dn", columnDefinition = "TEXT")
    private String subjectDn;

    @Column(name = "common_name", length = 255)
    private String commonName;

    @Column(name = "public_key_curve", length = 100)
    private String publicKeyCurve;

    @Column(name = "key_usage", length = 255)
    private String keyUsage;

    @Column(name = "extended_key_usage", columnDefinition = "TEXT")
    private String extendedKeyUsage;

    @Column(name = "subject_key_identifier", length = 200)
    private String subjectKeyIdentifier;

    @Column(name = "authority_key_identifier", length = 200)
    private String authorityKeyIdentifier;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = OffsetDateTime.now();
        updatedAt = OffsetDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
