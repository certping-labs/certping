// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * A local account's TOTP second factor. The secret is sealed with the password pepper and only a
 * confirmed row (the user produced one valid code during enrollment) makes sign-in ask for a code.
 */
@Entity
@Table(name = "user_mfa")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserMfa {

    @Id
    @Column(name = "user_id")
    private Integer userId;

    /** {@code $enc1$<pepperVersion>$<nonce>$<ciphertext>} over the raw secret bytes. */
    @Column(name = "secret_sealed", nullable = false)
    private String secretSealed;

    @Column(name = "confirmed_at")
    private OffsetDateTime confirmedAt;

    @Column(name = "last_used_step")
    private Long lastUsedStep;

    /** Comma-separated SHA-256 hex digests of the recovery codes not yet used; empty when none remain. */
    @Column(name = "recovery_code_hashes", nullable = false)
    @Builder.Default
    private String recoveryCodeHashes = "";

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    public boolean isConfirmed() {
        return confirmedAt != null;
    }

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
    }
}
