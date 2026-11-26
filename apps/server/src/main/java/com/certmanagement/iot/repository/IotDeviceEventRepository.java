// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.alert.OrganizationCount;
import com.certmanagement.iot.entity.IotDeviceEvent;
import com.certmanagement.iot.enums.DeviceEventType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;

public interface IotDeviceEventRepository extends JpaRepository<IotDeviceEvent, Long> {

    boolean existsByOrganizationIdAndDedupeKey(Long organizationId, String dedupeKey);

    /** Device detail timeline. Backed by idx_iot_event_device. */
    Page<IotDeviceEvent> findByDeviceIdAndOrganizationIdOrderByOccurredAtDesc(
            Long deviceId, Long organizationId, Pageable pageable);

    /** Org-wide feed, optionally narrowed to alertable types. Backed by idx_iot_event_org_type. */
    Page<IotDeviceEvent> findByOrganizationIdAndEventTypeInOrderByOccurredAtDesc(
            Long organizationId, Collection<DeviceEventType> eventTypes, Pageable pageable);

    Page<IotDeviceEvent> findByOrganizationIdOrderByOccurredAtDesc(Long organizationId, Pageable pageable);

    /** Certificate history timeline, newest first. */
    Page<IotDeviceEvent> findByCertificateEnrollmentIdAndOrganizationIdOrderByOccurredAtDesc(
            Long certificateEnrollmentId, Long organizationId, Pageable pageable);

    /** One row per (organization, event type) for the activity digest window. */
    interface DigestCount {
        Long getOrganizationId();
        DeviceEventType getEventType();
        long getTotal();
    }

    /**
     * Counts the digest-relevant events per organization for a window, in a single grouped scan.
     * Organizations with no activity simply do not appear, which is what keeps empty digests unsent.
     */
    @Query("""
            SELECT e.organizationId AS organizationId, e.eventType AS eventType, COUNT(e) AS total
              FROM IotDeviceEvent e
             WHERE e.occurredAt >= :from
               AND e.occurredAt < :to
               AND e.eventType IN :eventTypes
             GROUP BY e.organizationId, e.eventType
            """)
    List<DigestCount> countByOrganizationAndEventType(
            @Param("from") OffsetDateTime from,
            @Param("to") OffsetDateTime to,
            @Param("eventTypes") Collection<DeviceEventType> eventTypes);

    /**
     * Check-ins Intune throttled away. Native because the agent's error code lives inside the
     * event's jsonb detail, which is the only place a throttle is distinguishable from any other
     * failed nudge. Aliases are quoted so the projection still binds after PostgreSQL folds case.
     */
    @NativeQuery("""
            SELECT organization_id AS "organizationId", COUNT(*) AS "total"
              FROM iot_device_event
             WHERE occurred_at >= :from
               AND event_type = 'CERTIFICATE_NUDGE_FAILED'
               AND detail_json ->> 'errorCode' = 'PLATFORM_THROTTLED'
             GROUP BY organization_id
            """)
    List<OrganizationCount> countThrottledCheckIns(@Param("from") OffsetDateTime from);
}
