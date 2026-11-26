// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.RenewalStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLRestriction;

import java.time.OffsetDateTime;

@Entity
@Table(name = "renewal_schedule")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RenewalScheduleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "certificate_xref", nullable = false, unique = true, length = 100)
    private String certificateXref;

    /** FK to domain_credential_config — live credential config read at every renewal. */
    @Column(name = "domain_credential_config_id", nullable = false)
    private Long domainCredentialConfigId;

    @Column(name = "valid_to", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime validTo;

    @Column(name = "renewal_eligible_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime renewalEligibleAt;

    @Column(name = "renewal_window_days", nullable = false)
    @Builder.Default
    private Integer renewalWindowDays = 30;

    @Enumerated(EnumType.STRING)
    @Column(name = "ca_provider", nullable = false, length = 50)
    private CaProvider caProvider;

    @Column(name = "acme_account_handle", length = 500)
    private String acmeAccountHandle;

    @Column(name = "ca_credential_handle", length = 500)
    private String caCredentialHandle;

    @Column(name = "order_id", length = 64)
    private String orderId;

    @Column(name = "cert_secret_handle", length = 500)
    private String certSecretHandle;

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = false;

    @Column(name = "last_renewal_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime lastRenewalAt;

    @Column(name = "last_renewal_status", length = 50)
    private String lastRenewalStatus;

    @Column(name = "next_attempt_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime nextAttemptAt;

    /** Failed attempts in a row since the last renewal; the retry delay grows with it. */
    @Column(name = "consecutive_failures", nullable = false)
    @Builder.Default
    private Integer consecutiveFailures = 0;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = OffsetDateTime.now();
        updatedAt = OffsetDateTime.now();
        if (isDeleted == null) {
            isDeleted = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }

    /**
     * Whether a feature switch-off (CERTIFICATE_RENEWAL, or the DNS_CREDENTIALS its automatic work requires)
     * disabled this schedule. Its status is the marker that turns it back on, so a renewal that runs
     * meanwhile must not overwrite it.
     */
    public boolean heldByFeatureSwitch() {
        return !Boolean.TRUE.equals(enabled) && RenewalStatus.FEATURE_HOLD.name().equals(lastRenewalStatus);
    }
}
