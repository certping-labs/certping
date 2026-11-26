// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.alert.IotAlertPublisher;
import com.certmanagement.iot.alert.IotAlertPublisher.Severity;
import com.certmanagement.iot.alert.OrganizationCount;
import com.certmanagement.iot.certificate.IotCertificateEnrollmentRepository;
import com.certmanagement.iot.certificate.IotCertificateEnrollmentRepository.StatusCount;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.repository.IotDeviceEventRepository;
import com.certmanagement.iot.revocation.IotCertificateRevocationRepository;
import com.certmanagement.iot.revocation.IotCertificateRevocationStatus;
import com.certmanagement.repository.AgentHealthStatusRepository;
import com.certmanagement.repository.AgentHealthStatusRepository.HeartbeatState;
import com.certmanagement.service.FeatureFlagService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Sweeps the IoT fleet for conditions no single event can report, and alerts on the ones that need
 * a human.
 *
 * <p>These are states rather than events: an agent that stopped talking, certificates that were
 * nudged and never renewed, a revocation queue that stopped draining. Nothing happens at the moment
 * they go wrong, so only a periodic look finds them.
 *
 * <p>Runs hourly so a new problem surfaces within the hour, but every alert dedupes on the day, so a
 * condition that persists for a week is one alert a day rather than one an hour. Holds no state of
 * its own: findings are collected once at the start of a drain and emitted one per call.
 */
@Slf4j
@Service
@CronJobFor("trigger-iot-fleet-health-check")
public class IotFleetHealthCron implements DrainableCron {

    /** Matches AgentHealthService: a heartbeat is late once two cadences have passed. */
    private static final int MISSED_HEARTBEATS_FOR_STALE = 2;
    private static final Set<IotCertificateRevocationStatus> UNFINISHED_REVOCATIONS =
            Set.of(IotCertificateRevocationStatus.PENDING, IotCertificateRevocationStatus.DISPATCHED);
    private static final Set<String> FAILED_ENROLLMENT_STATUSES = Set.of("FAILED", "REJECTED");

    private final AgentHealthStatusRepository agentHealthRepository;
    private final IotCertificateEnrollmentRepository enrollmentRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotCertificateRevocationRepository revocationRepository;
    private final IotDeviceEventRepository eventRepository;
    private final IotAlertPublisher alertPublisher;
    private final FeatureFlagService featureFlagService;
    private final Clock clock;

    @Value("${certping.jobs.trigger-iot-fleet-health-check.lookback-hours:24}")
    private int lookbackHours;

    @Value("${certping.jobs.trigger-iot-fleet-health-check.enrollment-failure-minimum:10}")
    private int enrollmentFailureMinimum;

    @Value("${certping.jobs.trigger-iot-fleet-health-check.enrollment-failure-percent:25}")
    private int enrollmentFailurePercent;

    @Value("${certping.jobs.trigger-iot-fleet-health-check.throttled-check-in-minimum:20}")
    private int throttledCheckInMinimum;

    @Value("${certping.jobs.trigger-iot-fleet-health-check.nudge-stale-hours:48}")
    private int nudgeStaleHours;

    @Value("${certping.jobs.trigger-iot-fleet-health-check.unlinked-age-hours:24}")
    private int unlinkedAgeHours;

    @Value("${certping.jobs.trigger-iot-fleet-health-check.unlinked-minimum:5}")
    private int unlinkedMinimum;

    @Value("${certping.jobs.trigger-iot-fleet-health-check.revocation-stale-hours:6}")
    private int revocationStaleHours;

    private final Deque<Finding> pending = new ArrayDeque<>();
    private boolean loaded;

    public IotFleetHealthCron(AgentHealthStatusRepository agentHealthRepository,
                              IotCertificateEnrollmentRepository enrollmentRepository,
                              IotDeviceCertificateRepository certificateRepository,
                              IotCertificateRevocationRepository revocationRepository,
                              IotDeviceEventRepository eventRepository,
                              IotAlertPublisher alertPublisher,
                              FeatureFlagService featureFlagService,
                              Clock clock) {
        this.agentHealthRepository = agentHealthRepository;
        this.enrollmentRepository = enrollmentRepository;
        this.certificateRepository = certificateRepository;
        this.revocationRepository = revocationRepository;
        this.eventRepository = eventRepository;
        this.alertPublisher = alertPublisher;
        this.featureFlagService = featureFlagService;
        this.clock = clock;
    }

    private record Finding(Long organizationId, Severity severity, String scenario, String title,
                           String summary, Map<String, Object> facts) {}

    /**
     * Publishes one finding per call. Deliberately not transactional: the queries are reads and the
     * only write is an outbound publish, which no database transaction should span.
     */
    @Override
    public boolean tryProcessOneEligible() {
        if (!loaded) {
            collect();
            loaded = true;
        }
        Finding finding = pending.poll();
        if (finding == null) {
            loaded = false;
            return false;
        }
        try {
            publish(finding);
        } catch (Exception exception) {
            // One organization's alert must not abandon the rest of the sweep.
            log.error("[IotFleetHealthCron] Alert failed for org={} scenario={}: {}",
                    finding.organizationId(), finding.scenario(), exception.getMessage(), exception);
        }
        return true;
    }

    private void collect() {
        OffsetDateTime now = OffsetDateTime.now(clock);
        OffsetDateTime from = now.minusHours(lookbackHours);
        pending.clear();

        collectOfflineAgents(now);
        collectEnrollmentFailureSpikes(from);
        collectSustainedThrottling(from);
        collectStuckNudges(now);
        collectUnmanageableCertificates(now, from);
        collectRevocationBacklog(now);

        log.info("[IotFleetHealthCron] Sweep found {} condition(s) needing attention", pending.size());
    }

    /** A silent agent means no issuance, no renewal check-in and no revocation. */
    private void collectOfflineAgents(OffsetDateTime now) {
        for (HeartbeatState state : agentHealthRepository.findHeartbeatState()) {
            int cadence = state.getCadenceMinutes() == null ? 5 : state.getCadenceMinutes();
            long staleAfterMinutes = (long) cadence * MISSED_HEARTBEATS_FOR_STALE;
            OffsetDateTime lastSeen = state.getCmsReceivedAt();
            if (lastSeen != null
                    && Duration.between(lastSeen, now).toMinutes() < staleAfterMinutes) {
                continue;
            }
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("lastHeartbeatAt", lastSeen == null ? "never" : lastSeen.toString());
            facts.put("expectedEveryMinutes", cadence);
            facts.put("reportedStatus", state.getOverallStatus());
            facts.put("lastErrorCode", state.getLastErrorCode());
            add(state.getOrganizationId(), Severity.CRITICAL, "AGENT_OFFLINE",
                    "The CertPing agent has stopped reporting in",
                    "No heartbeat has arrived for at least " + staleAfterMinutes + " minutes. While "
                            + "the agent is down, devices cannot enroll or renew and revocations "
                            + "cannot reach the certificate authority.",
                    facts);
        }
    }

    /** Individual enrollment failures are digest material; a sustained rate is not. */
    private void collectEnrollmentFailureSpikes(OffsetDateTime from) {
        Map<Long, long[]> totals = new HashMap<>();
        for (StatusCount row : enrollmentRepository.countByOrganizationAndStatus(from)) {
            long[] counters = totals.computeIfAbsent(row.getOrganizationId(), key -> new long[2]);
            counters[0] += row.getTotal();
            if (FAILED_ENROLLMENT_STATUSES.contains(row.getStatus())) {
                counters[1] += row.getTotal();
            }
        }
        totals.forEach((organizationId, counters) -> {
            long attempted = counters[0];
            long failed = counters[1];
            if (failed < enrollmentFailureMinimum || attempted == 0) {
                return;
            }
            long percent = failed * 100 / attempted;
            if (percent < enrollmentFailurePercent) {
                return;
            }
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("enrollmentsAttempted", attempted);
            facts.put("enrollmentsFailed", failed);
            facts.put("failureRatePercent", percent);
            facts.put("windowHours", lookbackHours);
            add(organizationId, Severity.WARNING, "ENROLLMENT_FAILURE_SPIKE",
                    "Device enrollments are failing at an unusual rate",
                    failed + " of " + attempted + " enrollments failed in the last " + lookbackHours
                            + " hours. A rate this high is usually one profile, one connection or "
                            + "one certificate authority rather than the individual devices.",
                    facts);
        });
    }

    /** Throttling that does not clear means renewal check-ins are silently dropped. */
    private void collectSustainedThrottling(OffsetDateTime from) {
        for (OrganizationCount row : eventRepository.countThrottledCheckIns(from)) {
            if (row.getTotal() < throttledCheckInMinimum) {
                continue;
            }
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("throttledCheckIns", row.getTotal());
            facts.put("windowHours", lookbackHours);
            add(row.getOrganizationId(), Severity.WARNING, "SUSTAINED_THROTTLING",
                    "Intune is throttling device check-in requests",
                    row.getTotal() + " check-in requests were throttled in the last " + lookbackHours
                            + " hours. Renewals still work while this lasts, but they are being "
                            + "delayed, and certificates close to expiry may not renew in time.",
                    facts);
        }
    }

    /** NUDGING is not terminal, so a stuck row expires quietly unless something looks. */
    private void collectStuckNudges(OffsetDateTime now) {
        OffsetDateTime nudgedBefore = now.minusHours(nudgeStaleHours);
        for (OrganizationCount row : certificateRepository.countStuckInNudging(nudgedBefore)) {
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("certificatesStuck", row.getTotal());
            facts.put("nudgedOverHoursAgo", nudgeStaleHours);
            add(row.getOrganizationId(), Severity.WARNING, "RENEWAL_NUDGE_STUCK",
                    "Devices were asked to renew and never did",
                    row.getTotal() + " certificate(s) were nudged more than " + nudgeStaleHours
                            + " hours ago and have still not renewed. The devices are either "
                            + "offline, no longer enrolled, or not applying the certificate profile.",
                    facts);
        }
    }

    /** A certificate nobody can attribute to a device cannot be renewed or revoked. */
    private void collectUnmanageableCertificates(OffsetDateTime now, OffsetDateTime from) {
        Map<Long, long[]> byOrganization = new LinkedHashMap<>();
        for (OrganizationCount row : certificateRepository.countUnlinked(now.minusHours(unlinkedAgeHours))) {
            byOrganization.computeIfAbsent(row.getOrganizationId(), key -> new long[2])[0] = row.getTotal();
        }
        for (OrganizationCount row : enrollmentRepository.countAmbiguousDeviceMatches(from)) {
            byOrganization.computeIfAbsent(row.getOrganizationId(), key -> new long[2])[1] = row.getTotal();
        }
        byOrganization.forEach((organizationId, counters) -> {
            long unlinked = counters[0];
            long ambiguous = counters[1];
            if (unlinked + ambiguous < unlinkedMinimum) {
                return;
            }
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("certificatesUnlinked", unlinked);
            facts.put("enrollmentsAmbiguous", ambiguous);
            facts.put("unlinkedOverHoursOld", unlinkedAgeHours);
            add(organizationId, Severity.WARNING, "CERTIFICATES_NOT_ATTRIBUTABLE",
                    "Device certificates are not linked to a device",
                    (unlinked + ambiguous) + " certificate(s) exist without a device CertPing can "
                            + "name. They are live and trusted, but they cannot be renewed or "
                            + "revoked through the device, so they will not appear in device views.",
                    facts);
        });
    }

    /** A revocation that never completes leaves a certificate the operator thinks is dead. */
    private void collectRevocationBacklog(OffsetDateTime now) {
        OffsetDateTime createdBefore = now.minusHours(revocationStaleHours);
        List<OrganizationCount> rows =
                revocationRepository.countUnfinished(UNFINISHED_REVOCATIONS, createdBefore);
        for (OrganizationCount row : rows) {
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("revocationsOutstanding", row.getTotal());
            facts.put("olderThanHours", revocationStaleHours);
            add(row.getOrganizationId(), Severity.CRITICAL, "REVOCATION_BACKLOG",
                    "Revocations are not completing",
                    row.getTotal() + " revocation(s) requested more than " + revocationStaleHours
                            + " hours ago have still not been confirmed by the certificate "
                            + "authority. Treat those certificates as still trusted.",
                    facts);
        }
    }

    private void add(Long organizationId, Severity severity, String scenario, String title,
                     String summary, Map<String, Object> facts) {
        if (organizationId != null) {
            pending.add(new Finding(organizationId, severity, scenario, title, summary, facts));
        }
    }

    private void publish(Finding finding) {
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, finding.organizationId())) {
            return;
        }
        // Dedupes on the day, so an hourly sweep over a condition that lasts a week alerts seven
        // times rather than a hundred and sixty-eight.
        alertPublisher.publish(finding.severity(), finding.organizationId(), finding.scenario(),
                finding.title(), finding.summary(), IotAlertPublisher.dayBucket(), null,
                finding.facts());
    }
}
