// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DiscoveryScanEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface DiscoveryScanRepository extends JpaRepository<DiscoveryScanEntity, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT scan FROM DiscoveryScanEntity scan WHERE scan.requestId = :requestId")
    Optional<DiscoveryScanEntity> findByRequestIdForUpdate(@Param("requestId") String requestId);
}
