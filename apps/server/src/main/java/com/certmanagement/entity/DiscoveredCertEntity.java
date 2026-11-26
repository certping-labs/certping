// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import com.certmanagement.service.cbom.CertificateInventoryEntityListener;
import tools.jackson.databind.JsonNode;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

/**
 * Persists a certificate discovered from a customer's cloud infrastructure by the agent.
 *
 * <p>One row per (organization_id, resource_id) pair — upserted on each discovery run
 * so repeated scans refresh metadata rather than creating duplicates.
 *
 * <p>The {@code managed} flag indicates whether this certificate is also managed by
 * CertPing, determined by matching its (normalized) serial number against a
 * CertPing-issued certificate for the same organization. {@code null} means the status
 * could not be evaluated — typically because the source did not report a serial number.
 */
@Entity
@Table(
    name = "discovered_cert",
    uniqueConstraints = @UniqueConstraint(
        name = "uq_discovered_cert_org_resource",
        columnNames = {"organization_id", "resource_id"}
    )
)
@EntityListeners(CertificateInventoryEntityListener.class)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DiscoveredCertEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    /** Idempotency key from the discovery command that produced this row. */
    @Column(name = "request_id", nullable = false, length = 100)
    private String requestId;

    /** Target type that was scanned (e.g. AWS_ACM). Matches TargetType enum string value. */
    @Column(name = "target_type", nullable = false, length = 50)
    private String targetType;

    /** Provider-native resource identifier (e.g. ACM certificate ARN). */
    @Column(name = "resource_id", nullable = false, columnDefinition = "TEXT")
    private String resourceId;

    @Column(name = "domain", length = 500)
    private String domain;

    @Column(name = "key_algorithm", length = 100)
    private String keyAlgorithm;

    @Column(name = "signature_algorithm", length = 100)
    private String signatureAlgorithm;

    @Column(name = "not_before", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime notBefore;

    @Column(name = "not_after", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime notAfter;

    @Column(name = "issuer", columnDefinition = "TEXT")
    private String issuer;

    @Column(name = "serial_number", length = 200)
    private String serialNumber;

    /** Status as reported by the cloud provider (e.g. ISSUED, EXPIRED, REVOKED). */
    @Column(name = "cert_status", length = 50)
    private String certStatus;

    /** Provider resources currently using this certificate (e.g. ALB listener ARNs). */
    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "in_use_by", columnDefinition = "text[]")
    private String[] inUseBy;

    /** Full subject distinguished name (e.g. "CN=test.example.net,O=CertPing Test"). */
    @Column(name = "subject_dn", columnDefinition = "TEXT")
    private String subjectDn;

    /** Subject Alternative Names — all domains this certificate covers. */
    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "san_domains", columnDefinition = "text[]")
    private String[] sanDomains;

    /**
     * Key usage flags as a comma-separated string (e.g. "DIGITAL_SIGNATURE,KEY_ENCIPHERMENT").
     * Used for HNDL risk classification.
     */
    @Column(name = "key_usage", length = 255)
    private String keyUsage;

    /** Extended key usage flags as a comma-separated string. */
    @Column(name = "extended_key_usage", columnDefinition = "TEXT")
    private String extendedKeyUsage;

    /**
     * Certificate origin as reported by the provider
     * (e.g. "AMAZON_ISSUED", "IMPORTED", "PRIVATE").
     */
    @Column(name = "cert_type", length = 50)
    private String certType;

    /** Latest provider-specific discovery details. Null for providers with no extension payload. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "provider_data", columnDefinition = "jsonb")
    private JsonNode providerData;

    @Enumerated(EnumType.STRING)
    @Column(name = "inventory_status", nullable = false, length = 20)
    @Builder.Default
    private DiscoveryInventoryStatus inventoryStatus = DiscoveryInventoryStatus.UNKNOWN;

    @Column(name = "missing_since", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime missingSince;

    /**
     * Tri-state: {@code true} when this cert's serial matches a CertPing-issued cert for
     * the same org, {@code false} when a serial was reported but did not match (external),
     * {@code null} when no serial was available to evaluate.
     */
    @Column(name = "managed")
    private Boolean managed;

    @Column(name = "discovered_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime discoveredAt;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        updatedAt = now;
        if (discoveredAt == null) {
            discoveredAt = now;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
