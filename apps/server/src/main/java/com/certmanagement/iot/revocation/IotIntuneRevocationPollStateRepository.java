// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;

import java.time.OffsetDateTime;
import java.util.Optional;

public interface IotIntuneRevocationPollStateRepository
        extends JpaRepository<IotIntuneRevocationPollState, Long> {
    Optional<IotIntuneRevocationPollState> findByDeviceSourceId(Long deviceSourceId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT state FROM IotIntuneRevocationPollState state "
            + "WHERE state.deviceSourceId = :deviceSourceId")
    Optional<IotIntuneRevocationPollState> findByDeviceSourceIdForUpdate(
            @Param("deviceSourceId") Long deviceSourceId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT state FROM IotIntuneRevocationPollState state WHERE state.id = :id")
    Optional<IotIntuneRevocationPollState> findByIdForUpdate(@Param("id") Long id);

    @Modifying
    @NativeQuery("""
            INSERT INTO iot_intune_revocation_poll_state (
                organization_id, device_source_id, status, attempt_count,
                next_attempt_at, created_at, updated_at)
            VALUES (:organizationId, :deviceSourceId, 'IDLE', 0, :now, :now, :now)
            ON CONFLICT (device_source_id) DO NOTHING
            """)
    void insertIfAbsent(@Param("organizationId") Long organizationId,
                        @Param("deviceSourceId") Long deviceSourceId,
                        @Param("now") OffsetDateTime now);

    @NativeQuery("""
            SELECT state.*
              FROM iot_intune_revocation_poll_state state
              JOIN iot_device_source source ON source.id = state.device_source_id
             WHERE source.status = 'ACTIVE'
               AND state.next_attempt_at <= :now
             ORDER BY state.next_attempt_at, state.id
             LIMIT 1
             FOR UPDATE OF state SKIP LOCKED
            """)
    Optional<IotIntuneRevocationPollState> claimNextDue(@Param("now") OffsetDateTime now);
}
