// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {

    @Query("SELECT b FROM BlacklistedToken b WHERE b.token.jti = :jti")
    Optional<BlacklistedToken> findByJti(@Param("jti") String jti);

    @Query("SELECT COUNT(b) > 0 FROM BlacklistedToken b WHERE b.token.jti = :jti")
    boolean existsByJti(@Param("jti") String jti);
}
