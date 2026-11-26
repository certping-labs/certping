// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.messaging.NotificationPublisher;
import com.certmanagement.repository.CertificateRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.CannotAcquireLockException;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ExpiryAlertServiceTest {

    private static final Long   ORG_ID = 5L;
    private static final String XREF   = "cert-alert-abc";

    @Mock private CertificateRepository  certificateRepository;
    @Mock private NotificationPublisher  notificationPublisher;

    @InjectMocks private ExpiryAlertService service;

    private CertificateEntity cert;

    @BeforeEach
    void setUp() {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(1L).organizationId(ORG_ID).domain("example.com").build();
        cert = CertificateEntity.builder()
                .certificateXref(XREF)
                .userDomainCert(udc)
                .status("ACTIVE")
                .validTo(OffsetDateTime.now().plusDays(10))
                .build();
    }

    @Test
    void tryProcessOneEligible_emptyQueue_returnsFalse() {
        when(certificateRepository.claimOneExpiringActiveForAlert(any(), any(), any()))
                .thenReturn(Optional.empty());

        assertThat(service.tryProcessOneEligible(30)).isFalse();
        verify(notificationPublisher, never()).publish(anyString(), anyString(), anyString(), any());
    }

    @Test
    void tryProcessOneEligible_success_marksAlertedAndPublishes() {
        when(certificateRepository.claimOneExpiringActiveForAlert(any(), any(), any()))
                .thenReturn(Optional.of(cert));

        boolean processed = service.tryProcessOneEligible(30);

        assertThat(processed).isTrue();
        verify(certificateRepository).recordExpiryAlert(eq(XREF), any(), eq(14));

        @SuppressWarnings({"rawtypes", "unchecked"})
        ArgumentCaptor<Map> payloadCap = ArgumentCaptor.forClass(Map.class);
        verify(notificationPublisher).publish(
                eq("CERT_EXPIRY_ALERT"), eq(ORG_ID.toString()), eq(XREF), payloadCap.capture());
        @SuppressWarnings("unchecked")
        Map<String, String> payload = payloadCap.getValue();
        assertThat(payload).containsEntry("domain", "example.com");
        assertThat(payload.get("daysRemaining")).isIn("9", "10");
        assertThat(payload).containsEntry("thresholdDays", "14");
    }

    @Test
    void tryProcessOneEligible_insideTheSameThreshold_staysQuietButStamps() {
        cert.setExpiryAlertThresholdDays(14);
        when(certificateRepository.claimOneExpiringActiveForAlert(any(), any(), any()))
                .thenReturn(Optional.of(cert));

        assertThat(service.tryProcessOneEligible(30)).isTrue();

        verify(certificateRepository).updateLastAlertedAt(eq(XREF), any());
        verify(certificateRepository, never()).recordExpiryAlert(any(), any(), anyInt());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    @Test
    void thresholdCrossed_alertsOncePerThresholdAndStartsOverAfterARenewal() {
        List<Integer> thresholds = ExpiryAlertService.DEFAULT_THRESHOLDS;
        assertThat(ExpiryAlertService.thresholdCrossed(45, null, thresholds)).as("outside every threshold").isNull();
        assertThat(ExpiryAlertService.thresholdCrossed(29, null, thresholds)).isEqualTo(30);
        assertThat(ExpiryAlertService.thresholdCrossed(20, 30, thresholds)).as("still in the 30-day band").isNull();
        assertThat(ExpiryAlertService.thresholdCrossed(14, 30, thresholds)).isEqualTo(14);
        assertThat(ExpiryAlertService.thresholdCrossed(2, 14, thresholds)).as("skips straight to the tightest").isEqualTo(3);
        assertThat(ExpiryAlertService.thresholdCrossed(0, 1, thresholds)).as("expiry day already covered").isNull();
        assertThat(ExpiryAlertService.thresholdCrossed(25, 7, thresholds)).as("validity moved out again").isEqualTo(30);
    }

    @Test
    void parseThresholds_acceptsAListAndFallsBackOnJunk() {
        assertThat(ExpiryAlertService.parseThresholds("60, 7,7, 0,-1")).containsExactly(60, 7);
        assertThat(ExpiryAlertService.parseThresholds("")).isEqualTo(ExpiryAlertService.DEFAULT_THRESHOLDS);
        assertThat(ExpiryAlertService.parseThresholds("soon")).isEqualTo(ExpiryAlertService.DEFAULT_THRESHOLDS);
    }

    /**
     * DrainRunner's loop has no per-row catch, and the claim is ORDER BY valid_to ASC LIMIT 1. If a
     * publish failure propagated, the same certificate would be re-selected and abort the drain on
     * every tick — one bad row would stop every alert, permanently.
     */
    @Test
    void tryProcessOneEligible_publishFailure_keepsDrainingAndDefersThatCertificate() {
        when(certificateRepository.claimOneExpiringActiveForAlert(any(), any(), any()))
                .thenReturn(Optional.of(cert));
        doThrow(new RuntimeException("notif down"))
                .when(notificationPublisher).publish(anyString(), anyString(), anyString(), any());

        OffsetDateTime before = OffsetDateTime.now();
        assertThat(service.tryProcessOneEligible(30)).isTrue();

        // The look is stamped (so the row leaves this drain) but the threshold is not recorded as sent.
        verify(certificateRepository, never()).recordExpiryAlert(any(), any(), anyInt());
        ArgumentCaptor<OffsetDateTime> stamped = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(certificateRepository).updateLastAlertedAt(eq(XREF), stamped.capture());
        // Eligible again after RETRY_AFTER: older than the 24h cutoff by then, newer than it now.
        assertThat(stamped.getValue()).isAfter(before.minus(ExpiryAlertService.LOOK_INTERVAL))
                .isBefore(before.minus(ExpiryAlertService.LOOK_INTERVAL).plus(ExpiryAlertService.RETRY_AFTER)
                        .plusMinutes(1));
    }

    /** A transient enqueue failure at a threshold must not cost that threshold's alert. */
    @Test
    void aPublishThatFailsOnceIsSentOnTheNextPass() {
        when(certificateRepository.claimOneExpiringActiveForAlert(any(), any(), any()))
                .thenReturn(Optional.of(cert));
        // The repository is a mock, so the row keeps whatever the service recorded: nothing on failure.
        doThrow(new RuntimeException("queue down")).doNothing()
                .when(notificationPublisher).publish(anyString(), anyString(), anyString(), any());

        assertThat(service.tryProcessOneEligible(30)).isTrue();
        verify(certificateRepository, never()).recordExpiryAlert(any(), any(), anyInt());
        assertThat(cert.getExpiryAlertThresholdDays()).isNull();

        assertThat(service.tryProcessOneEligible(30)).isTrue();

        @SuppressWarnings({"rawtypes", "unchecked"})
        ArgumentCaptor<Map> payloads = ArgumentCaptor.forClass(Map.class);
        verify(notificationPublisher, org.mockito.Mockito.times(2))
                .publish(eq("CERT_EXPIRY_ALERT"), eq(ORG_ID.toString()), eq(XREF), payloads.capture());
        assertThat(payloads.getAllValues()).allSatisfy(p -> assertThat(p).containsEntry("thresholdDays", "14"));
        verify(certificateRepository).recordExpiryAlert(eq(XREF), any(), eq(14));
    }

    /** Recording comes after the publish, in the same transaction: its failure aborts the drain and rolls both back. */
    @Test
    void tryProcessOneEligible_stampFailure_propagates() {
        when(certificateRepository.claimOneExpiringActiveForAlert(any(), any(), any()))
                .thenReturn(Optional.of(cert));
        doThrow(new CannotAcquireLockException("db down"))
                .when(certificateRepository).recordExpiryAlert(eq(XREF), any(), anyInt());

        assertThatThrownBy(() -> service.tryProcessOneEligible(30))
                .isInstanceOf(CannotAcquireLockException.class);

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(notificationPublisher, certificateRepository);
        order.verify(notificationPublisher).publish(any(), any(), any(), any());
        order.verify(certificateRepository).recordExpiryAlert(eq(XREF), any(), eq(14));
    }

    @Test
    void tryProcessOneEligible_nullValidTo_publishesWithZeroDaysRemaining() {
        cert.setValidTo(null);
        when(certificateRepository.claimOneExpiringActiveForAlert(any(), any(), any()))
                .thenReturn(Optional.of(cert));

        service.tryProcessOneEligible(30);

        @SuppressWarnings({"rawtypes", "unchecked"})
        ArgumentCaptor<Map> payloadCap = ArgumentCaptor.forClass(Map.class);
        verify(notificationPublisher).publish(any(), any(), any(), payloadCap.capture());
        @SuppressWarnings("unchecked")
        Map<String, String> payload = payloadCap.getValue();
        assertThat(payload).containsEntry("daysRemaining", "0");
        assertThat(payload).containsEntry("validTo", "");
    }
}
