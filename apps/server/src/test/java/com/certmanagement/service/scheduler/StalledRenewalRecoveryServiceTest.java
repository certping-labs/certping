// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cert.AbandonedRenewalCleanup;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StalledRenewalRecoveryServiceTest {

    private static final String SOURCE = "cert-source";

    @Mock private CertificateRepository certificates;
    @Mock private RenewalScheduleRepository schedules;
    @Mock private CertificateEventRepository events;
    @Mock private AbandonedRenewalCleanup cleanup;
    @Mock private CertificateAuditRecorder audit;

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private StalledRenewalRecoveryService service;

    @BeforeEach
    void setUp() {
        service = new StalledRenewalRecoveryService(certificates, schedules, events, cleanup, audit, meters);
    }

    @Test
    void nothingRenewingPastTheHorizonEndsTheDrain() {
        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);

        assertThat(service.tryProcessOneEligible()).isFalse();

        ArgumentCaptor<OffsetDateTime> cutoff = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(certificates).claimOneStalledRenewal(cutoff.capture());
        assertThat(cutoff.getValue()).isCloseTo(before.minus(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON),
                org.assertj.core.api.Assertions.within(5, ChronoUnit.SECONDS));
        assertThat(timeouts()).isZero();
    }

    @Test
    void anInProgressScheduleRecordsAFailureAndNothingIsSent() {
        CertificateEntity source = stalled();
        RenewalScheduleEntity schedule = schedule("IN_PROGRESS", true);
        when(cleanup.abandon(eq(source), any())).thenReturn(new AbandonedRenewalCleanup.Outcome("cert-draft", "ACTIVE"));
        when(schedules.findByCertificateXref(SOURCE)).thenReturn(Optional.of(schedule));

        assertThat(service.tryProcessOneEligible()).isTrue();

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FAILED");
        assertThat(schedule.getConsecutiveFailures()).isEqualTo(1);
        assertThat(schedule.getNextAttemptAt()).isAfter(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(14));
        verify(schedules).save(schedule);
        assertThat(timeouts()).isEqualTo(1);
    }

    @Test
    void aHeldScheduleKeepsItsHold() {
        CertificateEntity source = stalled();
        RenewalScheduleEntity schedule = schedule("FEATURE_HOLD", false);
        when(cleanup.abandon(eq(source), any())).thenReturn(new AbandonedRenewalCleanup.Outcome(null, "ACTIVE"));
        when(schedules.findByCertificateXref(SOURCE)).thenReturn(Optional.of(schedule));

        service.tryProcessOneEligible();

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FEATURE_HOLD");
        assertThat(schedule.getNextAttemptAt()).isNull();
        verify(schedules, never()).save(any());
    }

    @Test
    void aScheduleThatAlreadyFailedKeepsItsRetryTime() {
        CertificateEntity source = stalled();
        RenewalScheduleEntity schedule = schedule("FAILED", true);
        OffsetDateTime retryAt = OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(5);
        schedule.setNextAttemptAt(retryAt);
        when(cleanup.abandon(eq(source), any())).thenReturn(new AbandonedRenewalCleanup.Outcome(null, "ACTIVE"));
        when(schedules.findByCertificateXref(SOURCE)).thenReturn(Optional.of(schedule));

        service.tryProcessOneEligible();

        assertThat(schedule.getNextAttemptAt()).isEqualTo(retryAt);
        verify(schedules, never()).save(any());
    }

    @Test
    void aSupersededCertificateLeavesItsDisabledScheduleAlone() {
        CertificateEntity source = stalled();
        when(cleanup.abandon(eq(source), any()))
                .thenReturn(new AbandonedRenewalCleanup.Outcome(null, "RENEW_SUCCESS"));

        service.tryProcessOneEligible();

        verify(schedules, never()).findByCertificateXref(any());
        assertThat(timeouts()).isEqualTo(1);
    }

    @Test
    void theEndedAttemptIsRecordedAsAFailedRenewal() {
        CertificateEntity source = stalled();
        when(cleanup.abandon(eq(source), any())).thenReturn(new AbandonedRenewalCleanup.Outcome("cert-draft", "ACTIVE"));

        service.tryProcessOneEligible();

        ArgumentCaptor<CertificateEventEntity> event = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(events).save(event.capture());
        assertThat(event.getValue().getCertificateXref()).isEqualTo(SOURCE);
        assertThat(event.getValue().getEventType()).isEqualTo("RENEWAL_FAILED");
        assertThat(event.getValue().getFromStatus()).isEqualTo("RENEWING");
        assertThat(event.getValue().getToStatus()).isEqualTo("ACTIVE");
        assertThat(event.getValue().getDetails())
                .isEqualTo("{\"errorCode\":\"RENEWAL_RESPONSE_TIMEOUT\",\"renewedCertificateXref\":\"cert-draft\"}");
        verify(audit).renewalFailed(eq(source), eq(AuditReason.of("RENEWAL_RESPONSE_TIMEOUT")), isNull());
    }

    private CertificateEntity stalled() {
        CertificateEntity source = CertificateEntity.builder()
                .certificateXref(SOURCE)
                .userDomainCertId(7L)
                .status("RENEWING")
                .build();
        when(certificates.claimOneStalledRenewal(any())).thenReturn(Optional.of(source));
        return source;
    }

    private static RenewalScheduleEntity schedule(String status, boolean enabled) {
        return RenewalScheduleEntity.builder()
                .certificateXref(SOURCE)
                .lastRenewalStatus(status)
                .enabled(enabled)
                .build();
    }

    private double timeouts() {
        return meters.get(StalledRenewalRecoveryService.TIMEOUTS_METRIC).tag("kind", "renewal").counter().count();
    }
}
