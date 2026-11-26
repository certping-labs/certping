// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

/**
 * Ephemeral ACME order state for the manual certificate issuance flow.
 *
 * <p>Populated when the agent returns CERT_MANUAL_TXT_RESPONSE (containing the ACME order URL,
 * account key path, and TXT record list). Deleted once the certificate reaches ACTIVE or FAILED.
 *
 * <p>{@code certXref} is a {@code String} matching {@code certificates.certificate_xref}
 * (format: {@code "cert-<Long>"}), not a bare Long.
 */
@Entity
@Table(name = "cert_manual_issuance_state")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertManualIssuanceStateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Matches {@code certificates.certificate_xref} — a String in the form {@code "cert-<Long>"}.
     * NOT a bare Long column.
     */
    @Column(name = "cert_xref", nullable = false, unique = true, length = 100)
    private String certXref;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "acme_order_url", nullable = false, columnDefinition = "TEXT")
    private String acmeOrderUrl;

    @Column(name = "acme_account_handle", nullable = false, columnDefinition = "TEXT")
    private String acmeAccountHandle;

    /**
     * JSON array of TXT record objects — [{recordName, recordValue, domain}].
     * Stored as JSONB and re-sent to the agent on CERT_MANUAL_DNS_VALIDATE so the agent
     * can pre-verify DNS propagation without an extra ACME round-trip.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "txt_records", nullable = false, columnDefinition = "jsonb")
    private String txtRecords;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "deleted_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime deletedAt;

    /** Set to NOW() + 55 min. ACME orders expire in ~60 min after creation. */
    @Column(name = "expires_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime expiresAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = OffsetDateTime.now();
        if (isDeleted == null) isDeleted = false;
    }
}
