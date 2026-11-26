// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Represents a platform-wide feature flag stored in {@code global_feature_flags}.
 *
 * <p>This is a fixed catalog table — rows are seeded at startup and never deleted.
 * The {@code enabled} column is the only operational field modified at runtime.
 * No soft-delete pattern is used here.
 */
@Entity
@Table(name = "global_feature_flags")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GlobalFeatureFlag {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "feature_key", nullable = false, unique = true, length = 100)
    private String featureKey;

    @Column(name = "display_name", nullable = false, length = 255)
    private String displayName;

    @Column(name = "description")
    private String description;

    /**
     * Management scope: {@code ORG} (org admins or super admin may override per org) or
     * {@code PLATFORM} (super-admin global toggle only; no org-level rows in
     * {@code organization_feature_flags} or {@code org_type_feature_flags}).
     */
    @Column(name = "scope", nullable = false, length = 20)
    private String scope;

    /**
     * Catalog category, for display: {@code PLATFORM} or {@code B2B}. It no longer decides
     * resolution: every organization is of one type.
     */
    @Column(name = "category", nullable = false, length = 20)
    private String category;

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
