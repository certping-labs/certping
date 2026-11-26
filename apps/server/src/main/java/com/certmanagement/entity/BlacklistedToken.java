// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

/**
 * Marks an {@link OutstandingToken} as revoked. Refresh attempts whose JTI is on this
 * table must be rejected with 401.
 *
 * Backing table: {@code auth_revoked_refresh_tokens}.
 */
@Entity
@Table(name = "auth_revoked_refresh_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(exclude = {"token"})
public class BlacklistedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "token_id", nullable = false, unique = true)
    private OutstandingToken token;

    @Column(name = "blacklisted_at", nullable = false)
    private OffsetDateTime blacklistedAt;

    @PrePersist
    protected void onCreate() {
        if (blacklistedAt == null) {
            blacklistedAt = OffsetDateTime.now();
        }
    }
}
