// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.enums.CertEventType;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.enums.EventSource;
import com.certmanagement.enums.RenewalStatus;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cert.AbandonedRenewalCleanup;
import com.certmanagement.service.cert.RenewalRetryPolicy;
import com.certmanagement.util.MdcIds;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * Ends renewals whose agent result never arrived. A certificate still {@code RENEWING} after
 * {@link AbandonedRenewalCleanup#IN_FLIGHT_HORIZON} cannot get an answer any more, so its attempt is ended and
 * nothing is sent: an in-progress schedule records a failure, and the retry claim starts the next attempt
 * if the schedule allows it. A held schedule stays held. The sweep is keyed on the certificate, not the schedule,
 * because a manual renewal on a held schedule never marks the schedule in progress.
 */
@Slf4j
@Service
@CronJobFor("recover-stalled-renewals")
public class StalledRenewalRecoveryService implements DrainableCron {

    static final String TIMEOUTS_METRIC = "certping.certificate.attempt.timeouts";

    private final CertificateRepository certificateRepository;
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final CertificateEventRepository certEventRepository;
    private final AbandonedRenewalCleanup cleanup;
    private final CertificateAuditRecorder certificateAudit;
    private final Counter renewalTimeouts;

    public StalledRenewalRecoveryService(CertificateRepository certificateRepository,
                                         RenewalScheduleRepository renewalScheduleRepository,
                                         CertificateEventRepository certEventRepository,
                                         AbandonedRenewalCleanup cleanup,
                                         CertificateAuditRecorder certificateAudit,
                                         MeterRegistry meters) {
        this.certificateRepository = certificateRepository;
        this.renewalScheduleRepository = renewalScheduleRepository;
        this.certEventRepository = certEventRepository;
        this.cleanup = cleanup;
        this.certificateAudit = certificateAudit;
        this.renewalTimeouts = Counter.builder(TIMEOUTS_METRIC)
                .description("Certificate attempts ended because no agent result arrived in time")
                .tag("kind", "renewal")
                .register(meters);
        Counter.builder(AbandonedRenewalCleanup.RESULT_AFTER_TIMEOUT_METRIC)
                .description("Agent results that arrived after their renewal attempt was ended")
                .tag("kind", "renewal")
                .register(meters);
    }

    /**
     * Claims one certificate renewing for longer than the horizon and ends its attempt in one transaction.
     *
     * @return {@code true} if a certificate was claimed, {@code false} when none is left
     */
    @Override
    @Transactional
    public boolean tryProcessOneEligible() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        Optional<CertificateEntity> claimed = certificateRepository.claimOneStalledRenewal(
                now.minus(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON));
        if (claimed.isEmpty()) {
            return false;
        }
        CertificateEntity source = claimed.get();

        AbandonedRenewalCleanup.Outcome outcome = cleanup.abandon(source, now);
        if (outcome.renewable()) {
            renewalScheduleRepository.findByCertificateXref(source.getCertificateXref())
                    .ifPresent(this::releaseInProgress);
        }
        recordTimeout(source, outcome);
        renewalTimeouts.increment();
        log.warn("[RENEWAL_RESPONSE_TIMEOUT] xref={} org={} draft={} now={}",
                source.getCertificateXref(), source.getOrganizationId(), outcome.draftXref(),
                outcome.restoredStatus());
        return true;
    }

    /** An attempt that never answered counts as a failure, retried when due; a hold keeps its status. */
    private void releaseInProgress(RenewalScheduleEntity schedule) {
        if (schedule.heldByFeatureSwitch()
                || !RenewalStatus.IN_PROGRESS.name().equals(schedule.getLastRenewalStatus())) {
            return;
        }
        RenewalRetryPolicy.recordFailure(schedule);
        renewalScheduleRepository.save(schedule);
    }

    private void recordTimeout(CertificateEntity source, AbandonedRenewalCleanup.Outcome outcome) {
        certEventRepository.save(CertificateEventEntity.builder()
                .certificateXref(source.getCertificateXref())
                .organizationId(source.getOrganizationId())
                .eventType(CertEventType.RENEWAL_FAILED.name())
                .fromStatus(CertificateStatus.RENEWING.name())
                .toStatus(outcome.restoredStatus())
                .requestId(MdcIds.requestId())
                .correlationId(MdcIds.correlationId())
                .source(EventSource.SCHEDULER.value())
                .details("{\"errorCode\":\"" + AbandonedRenewalCleanup.RESPONSE_TIMEOUT
                        + "\",\"renewedCertificateXref\":\"" + (outcome.draftXref() == null ? "" : outcome.draftXref())
                        + "\"}")
                .build());
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.RENEWAL_RECOVERY_JOB,
                source.getOrganizationId())) {
            certificateAudit.renewalFailed(source, AuditReason.of(AbandonedRenewalCleanup.RESPONSE_TIMEOUT), null);
        }
    }
}
