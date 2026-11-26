// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

/**
 * Every refresh token we issue is recorded here so we can blacklist its JTI on logout
 * or password reset. See {@link BlacklistedToken} for the revocation side.
 *
 * <p>{@code authMethod} records HOW the session that minted this token was started:
 * {@code LOCAL} (password sign-in) or {@code SSO} (single sign-on). Distinct from
 * {@link User#authMethod}, which is account-level (whether the user has a password).</p>
 *
 * Backing table: {@code auth_refresh_tokens}.
 */
@Entity
@Table(name = "auth_refresh_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(exclude = {"user"})
@ToString(exclude = {"token", "user"})
public class OutstandingToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String jti;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String token;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    /**
     * Session-origin tag — {@code LOCAL} | {@code SSO}.
     * See class javadoc and {@link com.certmanagement.constants.JwtClaims} constants.
     */
    @Column(name = "auth_method", nullable = false, length = 20)
    private String authMethod;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = OffsetDateTime.now();
        }
    }
}
