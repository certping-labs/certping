// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLRestriction;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Organization-level feature flag override stored in {@code organization_feature_flags}.
 *
 * <p>A row here exists only when an org admin or a super admin has explicitly overridden the global
 * default. A super admin's row is {@code adminLocked}: it outranks the org-type default and the org
 * admin can neither change nor remove it. The effective flag value is resolved by
 * {@link com.certmanagement.service.FeatureFlagResolver}.
 *
 * <p>Only flags with {@code scope = 'ORG'} may have org-level overrides.
 * {@code scope = 'PLATFORM'} flags have no rows in this table.
 */
@Entity
@Table(name = "organization_feature_flags")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrganizationFeatureFlag {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    @Column(name = "feature_key", nullable = false, length = 100)
    private String featureKey;

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Column(name = "admin_locked", nullable = false)
    @Builder.Default
    private Boolean adminLocked = false;

    @Column(name = "updated_by_user_id")
    private Integer updatedByUserId;

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = OffsetDateTime.now(ZoneOffset.UTC);
        updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
        if (isDeleted == null) isDeleted = false;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
    }
}
