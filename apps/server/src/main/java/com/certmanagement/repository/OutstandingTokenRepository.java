// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.OutstandingToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface OutstandingTokenRepository extends JpaRepository<OutstandingToken, Long> {

    Optional<OutstandingToken> findByJti(String jti);

    List<OutstandingToken> findByUserId(Integer userId);

    /**
     * All outstanding refresh tokens for a user that have NOT already been blacklisted.
     * Used by {@code RefreshTokenService.revokeAllForUser} so we don't insert duplicate
     * blacklist rows for tokens that are already revoked.
     */
    @Query("""
        SELECT o FROM OutstandingToken o
         WHERE o.user.id = :userId
           AND o.expiresAt > :now
           AND o.id NOT IN (SELECT b.token.id FROM BlacklistedToken b)
        """)
    List<OutstandingToken> findActiveByUserId(@Param("userId") Integer userId,
                                              @Param("now") OffsetDateTime now);
}
