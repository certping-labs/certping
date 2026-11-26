// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLRestriction;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Represents the stable identity of a (organization, domain) pair.
 *
 * <p>Each domain a organization ever issues a certificate for has exactly one row here.
 * {@link CertificateEntity} and {@link DomainCredentialConfigEntity} both FK to this table
 * so organization + domain identity are stored once and joined rather than denormalised everywhere.
 *
 * <p>{@code userId} is nullable — a NULL value means the issuance was triggered by an API
 * key or the scheduler, not an interactive user.
 */
@Entity
@Table(name = "user_domain_certificate")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDomainCertEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "domain", nullable = false, length = 255)
    private String domain;

    /** Nullable — null means the issuance was not triggered by an interactive UI user. */
    @Column(name = "user_id")
    private Integer userId;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "deleted_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime deletedAt;

    @Column(name = "created", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime created;

    @Column(name = "updated", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updated;

    @PrePersist
    protected void onCreate() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        created = now;
        updated = now;
        if (isDeleted == null) {
            isDeleted = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updated = OffsetDateTime.now(ZoneOffset.UTC);
    }
}
