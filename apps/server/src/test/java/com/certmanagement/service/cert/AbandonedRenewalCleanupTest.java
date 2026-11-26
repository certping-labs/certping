// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AbandonedRenewalCleanupTest {

    private static final long UDC = 7L;
    private static final String SOURCE = "cert-source";
    private static final OffsetDateTime NOW = OffsetDateTime.of(2026, 10, 20, 12, 0, 0, 0, ZoneOffset.UTC);

    @Mock private CertificateRepository certificates;
    @Mock private RenewalScheduleRepository schedules;

    private AbandonedRenewalCleanup cleanup;

    @BeforeEach
    void setUp() {
        cleanup = new AbandonedRenewalCleanup(certificates, schedules);
    }

    @Test
    void theHorizonOutlastsTheRenewalCommandsTimeToLive() {
        assertThat(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON)
                .isEqualTo(CertAgentPublisher.RENEWAL_TIME_TO_LIVE.plusHours(12))
                .isEqualTo(Duration.ofHours(180));
    }

    @Test
    void theHorizonLeavesMostOfTheDefaultRenewalWindowToRenewIn() {
        Duration defaultRenewalWindow = Duration.ofDays(30);

        assertThat(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON).isLessThanOrEqualTo(defaultRenewalWindow.dividedBy(2));
    }

    @Test
    void failsTheDraftAndReturnsAValidCertificateToActive() {
        CertificateEntity draft = certificate("cert-draft", "PENDING", null);
        when(certificates.findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC, "PENDING"))
                .thenReturn(Optional.of(draft));

        AbandonedRenewalCleanup.Outcome outcome = cleanup.abandon(
                certificate(SOURCE, "RENEWING", NOW.plusDays(20)), NOW);

        assertThat(outcome).isEqualTo(new AbandonedRenewalCleanup.Outcome("cert-draft", "ACTIVE"));
        assertThat(outcome.renewable()).isTrue();
        ArgumentCaptor<CertificateEntity> saved = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificates).save(saved.capture());
        assertThat(saved.getValue().getStatus()).isEqualTo("RENEWAL_FAILED");
        assertThat(saved.getValue().getLastErrorCode()).isEqualTo("RENEWAL_RESPONSE_TIMEOUT");
        assertThat(saved.getValue().getLastErrorAt()).isEqualTo(NOW);
        verify(certificates).updateStatus(SOURCE, "ACTIVE");
        verify(schedules, never()).disableSchedule(anyString());
    }

    @Test
    void aCertificatePastItsValidityGoesBackToExpired() {
        AbandonedRenewalCleanup.Outcome outcome = cleanup.abandon(
                certificate(SOURCE, "RENEWING", NOW.minusMinutes(1)), NOW);

        assertThat(outcome).isEqualTo(new AbandonedRenewalCleanup.Outcome(null, "EXPIRED"));
        assertThat(outcome.renewable()).isTrue();
        verify(certificates).updateStatus(SOURCE, "EXPIRED");
        verify(certificates, never()).save(any());
    }

    @Test
    void aCertificateSupersededByAnotherActiveOneIsRetiredWithItsSchedule() {
        when(certificates.findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC, "PENDING"))
                .thenReturn(Optional.empty());
        when(certificates.findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC, "ACTIVE"))
                .thenReturn(Optional.of(certificate("cert-reissued", "ACTIVE", NOW.plusDays(80))));

        AbandonedRenewalCleanup.Outcome outcome = cleanup.abandon(
                certificate(SOURCE, "RENEWING", NOW.plusDays(20)), NOW);

        assertThat(outcome.restoredStatus()).isEqualTo("RENEW_SUCCESS");
        assertThat(outcome.renewable()).isFalse();
        verify(certificates).updateStatus(SOURCE, "RENEW_SUCCESS");
        verify(schedules).disableSchedule(SOURCE);
    }

    @Test
    void aCertificateNoLongerRenewingKeepsItsStatus() {
        AbandonedRenewalCleanup.Outcome outcome = cleanup.abandon(
                certificate(SOURCE, "ACTIVE", NOW.plusDays(20)), NOW);

        assertThat(outcome).isEqualTo(new AbandonedRenewalCleanup.Outcome(null, null));
        assertThat(outcome.renewable()).isFalse();
        verify(certificates, never()).updateStatus(anyString(), anyString());
    }

    private static CertificateEntity certificate(String xref, String status, OffsetDateTime validTo) {
        return CertificateEntity.builder()
                .certificateXref(xref)
                .userDomainCertId(UDC)
                .status(status)
                .validTo(validTo)
                .build();
    }
}
