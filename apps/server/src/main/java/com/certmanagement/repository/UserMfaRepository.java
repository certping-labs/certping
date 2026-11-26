// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.UserMfa;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserMfaRepository extends JpaRepository<UserMfa, Integer> {

    /** Whether sign-in must ask {@code userId} for a code: a confirmed enrollment exists. */
    @Query("SELECT COUNT(m) > 0 FROM UserMfa m WHERE m.userId = :userId AND m.confirmedAt IS NOT NULL")
    boolean isEnabled(@Param("userId") Integer userId);
}
