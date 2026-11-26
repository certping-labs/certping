// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.entity.IotDeviceSourceEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

public interface IotDeviceSourceEventRepository extends JpaRepository<IotDeviceSourceEvent, Long> {
    @Modifying
    @NativeQuery("""
            INSERT INTO iot_device_source_event (
                event_xref, organization_id, device_source_id, event_type, event_status,
                detail_json, occurred_at, received_at, correlation_id, dedupe_key)
            VALUES (
                :eventXref, :organizationId, :sourceId, :eventType, :eventStatus,
                CAST(:detailJson AS jsonb), :occurredAt, :receivedAt, :correlationId, :dedupeKey)
            ON CONFLICT (device_source_id, dedupe_key) DO NOTHING
            """)
    int insertIfAbsent(
            @Param("eventXref") String eventXref,
            @Param("organizationId") Long organizationId,
            @Param("sourceId") Long sourceId,
            @Param("eventType") String eventType,
            @Param("eventStatus") String eventStatus,
            @Param("detailJson") String detailJson,
            @Param("occurredAt") OffsetDateTime occurredAt,
            @Param("receivedAt") OffsetDateTime receivedAt,
            @Param("correlationId") String correlationId,
            @Param("dedupeKey") String dedupeKey);

    Page<IotDeviceSourceEvent> findByDeviceSourceIdAndOrganizationIdOrderByOccurredAtDesc(
            Long deviceSourceId, Long organizationId, Pageable pageable);

    Page<IotDeviceSourceEvent> findByDeviceSourceIdAndOrganizationIdAndCorrelationIdOrderByOccurredAtDesc(
            Long deviceSourceId, Long organizationId, String correlationId, Pageable pageable);

    Optional<IotDeviceSourceEvent> findByDeviceSourceIdAndDedupeKey(
            Long deviceSourceId, String dedupeKey);

    boolean existsByDeviceSourceIdAndEventType(
            Long deviceSourceId, com.certmanagement.iot.enums.DeviceSourceEventType eventType);

    boolean existsByDeviceSourceIdAndCorrelationIdAndEventType(
            Long deviceSourceId,
            String correlationId,
            com.certmanagement.iot.enums.DeviceSourceEventType eventType);

    List<IotDeviceSourceEvent> findByDeviceSourceIdAndCorrelationIdAndEventType(
            Long deviceSourceId,
            String correlationId,
            com.certmanagement.iot.enums.DeviceSourceEventType eventType);

    @NativeQuery("""
            SELECT requested.*
              FROM iot_device_source_event requested
             WHERE requested.device_source_id = :sourceId
               AND requested.event_type = 'PROFILE_SYNC_REQUESTED'
               AND NOT EXISTS (
                    SELECT 1
                      FROM iot_device_source_event terminal
                     WHERE terminal.device_source_id = requested.device_source_id
                       AND terminal.correlation_id = requested.correlation_id
                       AND terminal.event_type IN ('PROFILE_SYNC_COMPLETED', 'PROFILE_SYNC_FAILED')
               )
             ORDER BY requested.occurred_at DESC
             LIMIT 1
            """)
    Optional<IotDeviceSourceEvent> findLatestOpenProfileSync(@Param("sourceId") Long sourceId);

    @NativeQuery("""
            SELECT event.*
              FROM iot_device_source_event event
             WHERE event.device_source_id = :sourceId
               AND event.organization_id = :organizationId
               AND jsonb_exists(event.detail_json, 'profileXref')
               AND event.detail_json ->> 'profileXref' = :profileXref
             ORDER BY event.occurred_at DESC
            """)
    Page<IotDeviceSourceEvent> findProfileEvents(
            @Param("sourceId") Long sourceId,
            @Param("organizationId") Long organizationId,
            @Param("profileXref") String profileXref,
            Pageable pageable);
}
