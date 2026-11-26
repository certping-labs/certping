// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.GlobalSettingsEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Optional;

@Repository
public interface GlobalSettingsRepository extends JpaRepository<GlobalSettingsEntity, String> {

    @Modifying
    @Query("""
            UPDATE GlobalSettingsEntity g
            SET g.value = :value, g.updatedAt = :now, g.updatedBy = :updatedBy
            WHERE g.key = :key
            """)
    int updateValue(@Param("key") String key,
                    @Param("value") String value,
                    @Param("now") OffsetDateTime now,
                    @Param("updatedBy") Long updatedBy);

    /** The setting, locked until the transaction ends, so a read-then-write records the right "before". */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT g FROM GlobalSettingsEntity g WHERE g.key = :key")
    Optional<GlobalSettingsEntity> findByKeyForUpdate(@Param("key") String key);
}
