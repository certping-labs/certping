// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import com.certmanagement.service.cbom.CertificateInventoryEntityListener;
import com.certmanagement.enums.CaAccountSource;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.KeyCustody;
import com.certmanagement.enums.CertType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.OffsetDateTime;

/**
 * Primary certificate record.
 *
 * <p>Organization and domain identity are no longer stored directly on this entity — they
 * live in {@link UserDomainCertEntity} and are joined via {@code userDomainCert}.
 * Convenience methods {@link #getDomain()} and {@link #getOrganizationId()} delegate to that
 * relationship so existing callers require no changes.
 *
 * <p>Removed columns (moved to other tables):
 * <ul>
 *   <li>{@code organization_id}, {@code domain} — now in {@link UserDomainCertEntity}</li>
 *   <li>{@code san_domain_entries}, {@code dns_provider}, {@code dns_credential_path}
 *       — now in {@link DomainCredentialConfigEntity}</li>
 * </ul>
 *
 * <p>Kept: {@code san_domains} (domain metadata), {@code acme_account_handle} (LE operational),
 * {@code ca_credential_handle} (CA API operational).
 */
@Entity
@Table(name = "certificates")
@SQLRestriction("deleted_at IS NULL")
@EntityListeners(CertificateInventoryEntityListener.class)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "certificate_xref", nullable = false, unique = true, length = 100)
    private String certificateXref;

    /**
     * FK to user_domain_certificate — carries organization + domain identity.
     * Raw Long stored for direct use in FK queries without a JOIN.
     */
    @Column(name = "user_domain_cert_id", nullable = false)
    private Long userDomainCertId;

    /**
     * insertable/updatable = false because the FK is managed via {@code userDomainCertId}.
     * Lazy: code that reads {@link #getDomain()} or {@link #getOrganizationId()} outside a
     * session (the agent response consumer has none) must load the certificate through a
     * {@link com.certmanagement.repository.CertificateRepository} finder that fetches it.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_domain_cert_id", insertable = false, updatable = false)
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private UserDomainCertEntity userDomainCert;

    @Column(name = "wildcard", nullable = false)
    @Builder.Default
    private Boolean wildcard = false;

    @Column(name = "san", nullable = false)
    @Builder.Default
    private Boolean san = false;

    /**
     * Plain list of SAN domain strings (domain metadata).
     * Not used for credential routing — that is handled by DomainCredentialConfigEntity.
     */
    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "san_domains", columnDefinition = "text[]")
    private String[] sanDomains;

    @Enumerated(EnumType.STRING)
    @Column(name = "ca_provider", nullable = false, length = 50)
    private CaProvider caProvider;

    /**
     * Validity period the caller requested (in days). Preserved here so renewals issue
     * with the same validity by default. Null for LE (which always issues 90d regardless)
     * and for certs created before the column was added (renewal falls back to 90d).
     */
    @Column(name = "requested_validity_days")
    private Integer requestedValidityDays;

    @Column(name = "status", nullable = false, length = 50)
    @Builder.Default
    private String status = "PENDING";

    /** Handle in the agent's secret store where the cert PEM bundle is stored. */
    @Column(name = "cert_secret_handle", length = 500)
    private String certSecretHandle;

    /**
     * Last-deployed resource ID (audit).
     * AZURE_KV: full cert URI  |  AWS_ACM: certificate ARN.
     */
    @Column(name = "target_resource_id", length = 1000)
    private String targetResourceId;

    /**
     * Let's Encrypt ACME account KV URI.
     * Updated from agent response on each LE issuance/renewal.
     * Kept on certificate as recovery anchor — survives renewal_schedule recreation.
     */
    @Column(name = "acme_account_handle", length = 500)
    private String acmeAccountHandle;

    /**
     * DigiCert CA API credential KV URI.
     * Kept for the same recovery-path reason as {@code acmeAccountHandle}.
     */
    @Column(name = "ca_credential_handle", length = 500)
    private String caCredentialHandle;

    // ── Certificate material ─────────────────────────────────────────────────
    @Column(name = "issuer", length = 500)
    private String issuer;

    @Column(name = "serial_number", length = 100)
    private String serialNumber;

    @Column(name = "fingerprint_sha256", length = 200)
    private String fingerprintSha256;

    @Column(name = "valid_from", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime validFrom;

    @Column(name = "valid_to", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime validTo;

    @Column(name = "signature_algorithm", length = 100)
    private String signatureAlgorithm;

    @Column(name = "public_key_algorithm", length = 50)
    private String publicKeyAlgorithm;

    @Column(name = "key_size")
    private Integer keySize;

    @Enumerated(EnumType.STRING)
    @Column(name = "cert_type", length = 20)
    private CertType certType;

    // ── Error tracking ───────────────────────────────────────────────────────
    @Column(name = "last_error_code", length = 100)
    private String lastErrorCode;

    @Column(name = "last_error_message", columnDefinition = "TEXT")
    private String lastErrorMessage;

    @Column(name = "last_error_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastErrorAt;

    /**
     * Per-operation trace id of the most recent failure (set alongside lastErrorCode). Surfaced to
     * the user as a support "Reference ID"; never carries system detail. Null until a failure.
     */
    @Column(name = "correlation_id", length = 100)
    private String correlationId;

    @Column(name = "last_alerted_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastAlertedAt;

    /** The days-before-expiry threshold the last expiry alert was sent for; null until the first. */
    @Column(name = "expiry_alert_threshold_days")
    private Integer expiryAlertThresholdDays;

    /** CA order ID (DigiCert); used as renewal_of_order_id on next renewal. */
    @Column(name = "order_id", length = 64)
    private String orderId;

    /**
     * Marks certs whose CSR and private key originate from a third-party CDN.
     * Null for standard certs. "AKAMAI_CPS" for certs whose CSR was obtained from
     * Akamai CPS — the private key stays with Akamai and the cert may only be deployed
     * to AKAMAI_CPS targets.
     */
    @Column(name = "special_certificate_type", length = 50)
    private String specialCertificateType;

    @Enumerated(EnumType.STRING)
    @Column(name = "key_custody", nullable = false, length = 20)
    @Builder.Default
    private KeyCustody keyCustody = KeyCustody.PLATFORM_HELD;

    /** The customer's CSR, kept only for a customer-held certificate. */
    @Column(name = "csr_pem", columnDefinition = "TEXT")
    private String csrPem;

    @Enumerated(EnumType.STRING)
    @Column(name = "ca_account_source", length = 20)
    private CaAccountSource caAccountSource;

    @Column(name = "ca_order_cost", precision = 10, scale = 2)
    private BigDecimal caOrderCost;

    @Column(name = "ca_order_currency", length = 3)
    private String caOrderCurrency;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @Column(name = "deleted_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime deletedAt;

    // ── Convenience accessors — delegate to UserDomainCertEntity ────────────

    /**
     * Returns the primary domain, sourced from the {@link UserDomainCertEntity}.
     * Returns {@code null} if the navigation is not populated or its row is soft-deleted.
     */
    public String getDomain() {
        UserDomainCertEntity udc = liveUserDomainCert();
        return udc != null ? udc.getDomain() : null;
    }

    /**
     * Returns the owning organization Long, sourced from the {@link UserDomainCertEntity}.
     * Returns {@code null} if the navigation is not populated or its row is soft-deleted.
     */
    public Long getOrganizationId() {
        UserDomainCertEntity udc = liveUserDomainCert();
        return udc != null ? udc.getOrganizationId() : null;
    }

    /**
     * Deleting a user soft-deletes its UDCs and leaves their certificates live. A fetched
     * association to such a row comes back null, but a lazy proxy to it throws on every use;
     * both read as null here.
     */
    private UserDomainCertEntity liveUserDomainCert() {
        if (!(userDomainCert instanceof HibernateProxy proxy)) {
            return userDomainCert;
        }
        try {
            return (UserDomainCertEntity) proxy.getHibernateLazyInitializer().getImplementation();
        } catch (EntityNotFoundException e) {
            return null;
        }
    }

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
