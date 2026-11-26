// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.entity.IotDeviceSourceSyncState;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface IotDeviceSourceSyncStateRepository
        extends JpaRepository<IotDeviceSourceSyncState, Long> {
    Optional<IotDeviceSourceSyncState> findBySyncXref(String syncXref);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT state FROM IotDeviceSourceSyncState state WHERE state.deviceSourceId = :sourceId")
    Optional<IotDeviceSourceSyncState> lockBySourceId(@Param("sourceId") Long sourceId);
}
