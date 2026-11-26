// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

public interface IotDeviceSourceRepository extends JpaRepository<IotDeviceSource, Long> {
    List<IotDeviceSource> findAllByOrganizationIdOrderByCreatedAtDesc(Long organizationId);

    Optional<IotDeviceSource> findBySourceXrefAndOrganizationId(String sourceXref, Long organizationId);

    Optional<IotDeviceSource> findByOrganizationIdAndConnectionProfileRef(
            Long organizationId, String connectionProfileRef);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @NativeQuery("""
            INSERT INTO iot_device_source (
                source_xref, organization_id, provider, source_category,
                connection_profile_ref, display_name, description,
                configuration_metadata_json, sync_enabled, status,
                first_advertised_at, last_advertised_at, created_at, updated_at,
                advertising_agent_token_id)
            VALUES (
                :sourceXref, :organizationId, :provider, :sourceCategory,
                :profileRef, :displayName, :description,
                CAST(:metadataJson AS jsonb), FALSE, 'ACTIVE',
                :advertisedAt, :advertisedAt, :receivedAt, :receivedAt,
                :agentTokenId)
            ON CONFLICT (organization_id, connection_profile_ref) DO UPDATE SET
                source_category = EXCLUDED.source_category,
                display_name = EXCLUDED.display_name,
                description = EXCLUDED.description,
                configuration_metadata_json = EXCLUDED.configuration_metadata_json,
                last_advertised_at = EXCLUDED.last_advertised_at,
                updated_at = EXCLUDED.updated_at,
                advertising_agent_token_id = COALESCE(EXCLUDED.advertising_agent_token_id,
                                                      iot_device_source.advertising_agent_token_id)
            WHERE iot_device_source.provider = EXCLUDED.provider
              AND EXCLUDED.last_advertised_at >= iot_device_source.last_advertised_at
            """)
    int upsertAdvertisement(
            @Param("sourceXref") String sourceXref,
            @Param("organizationId") Long organizationId,
            @Param("provider") String provider,
            @Param("sourceCategory") String sourceCategory,
            @Param("profileRef") String profileRef,
            @Param("displayName") String displayName,
            @Param("description") String description,
            @Param("metadataJson") String metadataJson,
            @Param("advertisedAt") OffsetDateTime advertisedAt,
            @Param("receivedAt") OffsetDateTime receivedAt,
            @Param("agentTokenId") Long agentTokenId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT source FROM IotDeviceSource source WHERE source.sourceXref = :sourceXref "
            + "AND source.organizationId = :organizationId")
    Optional<IotDeviceSource> lockBySourceXrefAndOrganizationId(
            @Param("sourceXref") String sourceXref,
            @Param("organizationId") Long organizationId);

    @NativeQuery("""
            SELECT source.*
              FROM iot_device_source source
              LEFT JOIN iot_device_source_sync_state sync_state
                ON sync_state.device_source_id = source.id
              JOIN iot_device_source_health_status health
                ON health.device_source_id = source.id
             WHERE source.status = 'ACTIVE'
               AND source.sync_enabled = TRUE
               AND source.provider IN (:providers)
               AND source.id NOT IN (:excludedSourceIds)
               AND health.health_status IN ('HEALTHY', 'DEGRADED')
               AND health.received_at >= :healthFreshAfter
               AND (sync_state.device_source_id IS NULL
                    OR (sync_state.sync_status = 'PENDING'
                        AND sync_state.completed_at IS NULL
                        AND sync_state.requested_at < :pendingBefore)
                    OR (sync_state.sync_status = 'RUNNING'
                        AND sync_state.completed_at IS NULL
                        AND sync_state.requested_at < :runningBefore)
                    OR (sync_state.sync_status NOT IN ('PENDING','RUNNING')
                        AND sync_state.completed_at IS NOT NULL
                        AND sync_state.completed_at < :dueBefore))
             ORDER BY sync_state.completed_at NULLS FIRST, source.id
             FOR UPDATE OF source SKIP LOCKED
             LIMIT 1
            """)
    Optional<IotDeviceSource> claimOneForSync(
            @Param("pendingBefore") OffsetDateTime pendingBefore,
            @Param("runningBefore") OffsetDateTime runningBefore,
            @Param("dueBefore") OffsetDateTime dueBefore,
            @Param("healthFreshAfter") OffsetDateTime healthFreshAfter,
            @Param("providers") List<String> providers,
            @Param("excludedSourceIds") List<Long> excludedSourceIds);

    List<IotDeviceSource> findAllByStatusAndSyncEnabledTrue(DeviceSourceStatus status);
}
