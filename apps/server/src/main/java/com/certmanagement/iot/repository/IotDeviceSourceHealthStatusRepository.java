// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.entity.IotDeviceSourceHealthStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;

public interface IotDeviceSourceHealthStatusRepository
        extends JpaRepository<IotDeviceSourceHealthStatus, Long> {

    @Modifying
    @NativeQuery("""
            INSERT INTO iot_device_source_health_status (
                device_source_id, last_health_xref, health_status, provider_status,
                status_message, health_metadata_json, agent_instance_xref, agent_sequence,
                check_started_at, observed_at, published_at, received_at, response_time_ms, updated_at)
            VALUES (
                :sourceId, :healthXref, :healthStatus, :providerStatus,
                :statusMessage, CAST(:healthMetadataJson AS jsonb), :agentInstanceXref, :agentSequence,
                :checkStartedAt, :observedAt, :publishedAt, :receivedAt, :responseTimeMs, :receivedAt)
            ON CONFLICT (device_source_id) DO UPDATE SET
                last_health_xref = EXCLUDED.last_health_xref,
                health_status = EXCLUDED.health_status,
                provider_status = EXCLUDED.provider_status,
                status_message = EXCLUDED.status_message,
                health_metadata_json = EXCLUDED.health_metadata_json,
                agent_instance_xref = EXCLUDED.agent_instance_xref,
                agent_sequence = EXCLUDED.agent_sequence,
                check_started_at = EXCLUDED.check_started_at,
                observed_at = EXCLUDED.observed_at,
                published_at = EXCLUDED.published_at,
                received_at = EXCLUDED.received_at,
                response_time_ms = EXCLUDED.response_time_ms,
                updated_at = EXCLUDED.updated_at
            WHERE (
                iot_device_source_health_status.agent_instance_xref = EXCLUDED.agent_instance_xref
                AND EXCLUDED.agent_sequence > iot_device_source_health_status.agent_sequence)
               OR (
                iot_device_source_health_status.agent_instance_xref <> EXCLUDED.agent_instance_xref
                AND EXCLUDED.observed_at > iot_device_source_health_status.observed_at)
            """)
    int upsertIfNewer(
            @Param("sourceId") Long sourceId,
            @Param("healthXref") String healthXref,
            @Param("healthStatus") String healthStatus,
            @Param("providerStatus") String providerStatus,
            @Param("statusMessage") String statusMessage,
            @Param("healthMetadataJson") String healthMetadataJson,
            @Param("agentInstanceXref") String agentInstanceXref,
            @Param("agentSequence") long agentSequence,
            @Param("checkStartedAt") OffsetDateTime checkStartedAt,
            @Param("observedAt") OffsetDateTime observedAt,
            @Param("publishedAt") OffsetDateTime publishedAt,
            @Param("receivedAt") OffsetDateTime receivedAt,
            @Param("responseTimeMs") Long responseTimeMs);
}
