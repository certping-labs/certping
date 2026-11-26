// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.repository.IotDeviceEventRepository;
import com.certmanagement.iot.repository.IotDeviceEventRepository.DigestCount;
import com.certmanagement.messaging.NotificationPublisher;
import com.certmanagement.service.FeatureFlagService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Rolls the IoT device-certificate lifecycle into one activity digest per organization per run.
 *
 * <p>Device certificates are issued and renewed continuously by SCEP, so notifying per event would
 * be unusable at fleet scale. The digest carries counts and a link back into Machine Identity
 * instead, and organizations with no activity in the window are skipped rather than sent an empty
 * summary.
 *
 * <p>Holds no state of its own: the window is derived from the run time, and cross-replica or
 * retry duplicates collapse downstream because {@code requestId} is a deterministic
 * {@code organization + window-day} key that the notifier treats as the natural key.
 */
@Slf4j
@Service
@CronJobFor("trigger-iot-activity-digest")
public class IotActivityDigestCron implements DrainableCron {

    static final String ACTION = "IOT_ACTIVITY_DIGEST";

    /** Only the event types the digest reports on; anything else must not keep a quiet org awake. */
    private static final Set<DeviceEventType> DIGEST_EVENT_TYPES = Set.of(
            DeviceEventType.CERTIFICATE_ISSUED,
            DeviceEventType.CERTIFICATE_ENROLLMENT_FAILED,
            DeviceEventType.CHALLENGE_REJECTED,
            DeviceEventType.CERTIFICATE_RENEWED,
            DeviceEventType.CERTIFICATE_NUDGE_REQUESTED,
            DeviceEventType.CERTIFICATE_REVOCATION_CONFIRMED,
            DeviceEventType.CERTIFICATE_REVOCATION_FAILED,
            DeviceEventType.CERTIFICATE_REVOCATION_OUTCOME_UNKNOWN,
            DeviceEventType.DEVICE_DISCOVERED,
            DeviceEventType.DEVICE_ARCHIVED,
            DeviceEventType.DEVICE_ORPHANED);

    private final IotDeviceEventRepository eventRepository;
    private final NotificationPublisher notificationPublisher;
    private final FeatureFlagService featureFlagService;
    private final Clock clock;

    @Value("${certping.jobs.trigger-iot-activity-digest.lookback-hours:24}")
    private int lookbackHours;

    private final Deque<Long> pendingOrganizations = new ArrayDeque<>();
    private Map<Long, Map<DeviceEventType, Long>> pendingCounts;
    private OffsetDateTime windowFrom;
    private OffsetDateTime windowTo;

    public IotActivityDigestCron(IotDeviceEventRepository eventRepository,
                                 NotificationPublisher notificationPublisher,
                                 FeatureFlagService featureFlagService,
                                 Clock clock) {
        this.eventRepository = eventRepository;
        this.notificationPublisher = notificationPublisher;
        this.featureFlagService = featureFlagService;
        this.clock = clock;
    }

    /**
     * Publishes one organization's digest per call. The window is loaded once at the start of a
     * drain and consumed from memory, so the grouped scan runs once rather than once per org.
     *
     * <p>Deliberately not transactional: the only write is an outbound publish, and no database
     * transaction should span that network call.
     */
    @Override
    public boolean tryProcessOneEligible() {
        if (pendingCounts == null) {
            loadWindow();
        }
        Long organizationId = pendingOrganizations.poll();
        if (organizationId == null) {
            pendingCounts = null;
            return false;
        }
        try {
            publishDigest(organizationId, pendingCounts.get(organizationId));
        } catch (Exception exception) {
            // One organization's notification must not abandon the rest of the drain.
            log.error("[IotActivityDigestCron] Digest failed for org={}: {}",
                    organizationId, exception.getMessage(), exception);
        }
        return true;
    }

    private void loadWindow() {
        windowTo = OffsetDateTime.now(clock);
        windowFrom = windowTo.minusHours(lookbackHours);
        pendingCounts = new LinkedHashMap<>();
        List<DigestCount> rows =
                eventRepository.countByOrganizationAndEventType(windowFrom, windowTo, DIGEST_EVENT_TYPES);
        for (DigestCount row : rows) {
            pendingCounts
                    .computeIfAbsent(row.getOrganizationId(), key -> new EnumMap<>(DeviceEventType.class))
                    .put(row.getEventType(), row.getTotal());
        }
        pendingOrganizations.addAll(pendingCounts.keySet());
        log.info("[IotActivityDigestCron] Window {} to {} produced activity for {} organization(s)",
                windowFrom, windowTo, pendingCounts.size());
    }

    private void publishDigest(Long organizationId, Map<DeviceEventType, Long> counts) {
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, organizationId)) {
            return;
        }
        long issued = count(counts, DeviceEventType.CERTIFICATE_ISSUED);
        long enrollmentsFailed = count(counts, DeviceEventType.CERTIFICATE_ENROLLMENT_FAILED)
                + count(counts, DeviceEventType.CHALLENGE_REJECTED);
        long renewed = count(counts, DeviceEventType.CERTIFICATE_RENEWED);
        long revoked = count(counts, DeviceEventType.CERTIFICATE_REVOCATION_CONFIRMED);
        long revocationsNeedingAttention = count(counts, DeviceEventType.CERTIFICATE_REVOCATION_FAILED)
                + count(counts, DeviceEventType.CERTIFICATE_REVOCATION_OUTCOME_UNKNOWN);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("requestId", digestRequestId(organizationId));
        details.put("windowStart", windowFrom.toString());
        details.put("windowEnd", windowTo.toString());
        details.put("windowHours", lookbackHours);
        details.put("certificatesIssued", issued);
        details.put("enrollmentsFailed", enrollmentsFailed);
        details.put("certificatesRenewed", renewed);
        details.put("certificatesRevoked", revoked);
        details.put("revocationsNeedingAttention", revocationsNeedingAttention);
        details.put("checkInsRequested", count(counts, DeviceEventType.CERTIFICATE_NUDGE_REQUESTED));
        details.put("devicesOnboarded", count(counts, DeviceEventType.DEVICE_DISCOVERED));
        details.put("devicesArchived", count(counts, DeviceEventType.DEVICE_ARCHIVED));
        details.put("devicesOrphaned", count(counts, DeviceEventType.DEVICE_ORPHANED));

        notificationPublisher.publish(ACTION, String.valueOf(organizationId), null, details);
        log.info("[IotActivityDigestCron] Digest published org={} issued={} failed={} renewed={} revoked={}",
                organizationId, issued, enrollmentsFailed, renewed, revoked);
    }

    /**
     * Stable per organization and window day, so a retry or a second replica publishing the same
     * digest collapses to one notification instead of mailing the organization twice.
     */
    private String digestRequestId(Long organizationId) {
        return "iot-digest:" + organizationId + ":" + windowTo.toLocalDate();
    }

    private static long count(Map<DeviceEventType, Long> counts, DeviceEventType eventType) {
        Long value = counts.get(eventType);
        return value == null ? 0L : value;
    }
}
