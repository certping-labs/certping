// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Org-type-level feature flag override stored in {@code org_type_feature_flags}.
 *
 * <p>A row here exists when a super admin has set a default for all organizations of a given
 * type (every organization is B2B). Only flags with {@code scope = 'ORG'} may have org-type overrides.
 *
 * <p>Resolution priority (highest to lowest):
 * <ol>
 *   <li>Global flag disabled → false for everyone</li>
 *   <li>Org-specific override in {@code organization_feature_flags}</li>
 *   <li>Org-type override (this table)</li>
 *   <li>Default: true</li>
 * </ol>
 */
@Entity
@Table(name = "org_type_feature_flags")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrgTypeFeatureFlag {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "org_type", nullable = false, length = 10)
    private String orgType;

    @Column(name = "feature_key", nullable = false, length = 100)
    private String featureKey;

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Column(name = "updated_by_user_id")
    private Integer updatedByUserId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = OffsetDateTime.now(ZoneOffset.UTC);
        updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
    }
}
