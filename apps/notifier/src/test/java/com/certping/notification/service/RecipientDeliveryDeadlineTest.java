// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.NotificationAction;
import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.model.NotificationEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpResponse;
import jakarta.mail.internet.InternetAddress;
import org.eclipse.angus.mail.smtp.SMTPAddressFailedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RecipientDeliveryDeadlineTest {

    @Test
    void aStalledWholeSendStopsBeforeTheClaimCanExpire() throws Exception {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        Duration lease = Duration.ofMinutes(5);
        DeliveryTimeouts timeouts = new DeliveryTimeouts("smtp", 100, 100, 100,
                Duration.ofMillis(10), lease);
        RecipientDelivery delivery = new RecipientDelivery(claims, provider, timeouts,
                new SimpleMeterRegistry(), new EmailCopies(""));
        NotificationEvent event = NotificationEvent.builder().requestId("deadline-1")
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();
        RecipientClaims.Claim claim = new RecipientClaims.Claim(1, OffsetDateTime.now(), System.nanoTime(), false);
        when(claims.lease()).thenReturn(lease);
        when(claims.claim(any(), any(), any(), any(), any())).thenReturn(new RecipientClaims.Claimed(claim));
        CountDownLatch startedSend = new CountDownLatch(1);
        CountDownLatch stopped = new CountDownLatch(1);
        doAnswer(invocation -> {
            startedSend.countDown();
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException interrupted) {
                stopped.countDown();
                Thread.currentThread().interrupt();
            }
            return null;
        }).when(provider).sendTemplatedEmail(any(), any(), any(), any());

        long started = System.nanoTime();
        try {
            assertThatThrownBy(() -> delivery.deliver(event, List.of("member@example.com"), "template", "subject",
                    Map.of(), "{}"))
                    .isInstanceOf(RetryableNotificationException.class)
                    .hasMessageContaining("deadline");
            assertThat(startedSend.await(1, TimeUnit.SECONDS)).isTrue();
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
            assertThat(stopped.await(1, TimeUnit.SECONDS)).isTrue();
            verify(claims, never()).markFailed(any(), any());
        } finally {
            delivery.stop();
        }
    }

    @Test
    void anAbortedSmtpSendKeepsItsClaimUntilTheLeaseEnds() {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        Duration lease = Duration.ofMinutes(5);
        DeliveryTimeouts timeouts = new DeliveryTimeouts("smtp", 100, 100, 100,
                Duration.ofMillis(10), lease);
        RecipientDelivery delivery = new RecipientDelivery(claims, provider, timeouts,
                new SimpleMeterRegistry(), new EmailCopies(""));
        RecipientClaims.Claim claim = new RecipientClaims.Claim(1, OffsetDateTime.now(), System.nanoTime(), false);
        when(claims.lease()).thenReturn(lease);
        when(claims.claim(any(), any(), any(), any(), any())).thenReturn(new RecipientClaims.Claimed(claim));
        doThrow(new EmailSendDeadlineException("SMTP deadline"))
                .when(provider).sendTemplatedEmail(any(), any(), any(), any());
        NotificationEvent event = NotificationEvent.builder().requestId("deadline-2")
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();

        try {
            assertThatThrownBy(() -> delivery.deliver(event, List.of("member@example.com"), "template", "subject",
                    Map.of(), "{}"))
                    .isInstanceOfSatisfying(RetryableNotificationException.class,
                            failure -> assertThat(failure.getRetryAfter()).isGreaterThan(Duration.ofMinutes(4)));
            verify(claims, never()).markFailed(any(), any());
        } finally {
            delivery.stop();
        }
    }

    @Test
    void aRefusedAddressIsMarkedPermanent() throws Exception {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        DeliveryTimeouts timeouts = new DeliveryTimeouts("smtp", 100, 100, 100,
                Duration.ofMillis(10), Duration.ofMinutes(5));
        RecipientDelivery delivery = new RecipientDelivery(claims, provider, timeouts,
                new SimpleMeterRegistry(), new EmailCopies(""));
        RecipientClaims.Claim claim = new RecipientClaims.Claim(1, OffsetDateTime.now(), System.nanoTime(), false);
        when(claims.lease()).thenReturn(Duration.ofMinutes(5));
        when(claims.claim(any(), any(), any(), any(), any())).thenReturn(new RecipientClaims.Claimed(claim));
        doThrow(new RuntimeException(new SMTPAddressFailedException(
                new InternetAddress("refused@example.com"), "RCPT TO", 550, "mailbox unavailable")))
                .when(provider).sendTemplatedEmail(any(), any(), any(), any());
        NotificationEvent event = NotificationEvent.builder().requestId("refused-1")
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();

        try {
            assertThatThrownBy(() -> delivery.deliver(event, List.of("refused@example.com"), "template", "subject",
                    Map.of(), "{}"))
                    .isInstanceOf(RecipientsRefusedException.class);
            verify(claims).markFailed(claim, "PERMANENT_FAILURE");
        } finally {
            delivery.stop();
        }
    }

    @Test
    void aPermanentlyRefusedRecipientIsNotSentAgain() {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        DeliveryTimeouts timeouts = new DeliveryTimeouts("smtp", 100, 100, 100,
                Duration.ofMillis(10), Duration.ofMinutes(5));
        RecipientDelivery delivery = new RecipientDelivery(claims, provider, timeouts,
                new SimpleMeterRegistry(), new EmailCopies(""));
        when(claims.claim(any(), any(), any(), any(), any())).thenReturn(new RecipientClaims.Permanent());
        NotificationEvent event = NotificationEvent.builder().requestId("refused-2")
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();

        try {
            assertThatThrownBy(() -> delivery.deliver(event, List.of("refused@example.com"), "template", "subject",
                    Map.of(), "{}"))
                    .isInstanceOf(RecipientsRefusedException.class);
            verify(provider, never()).sendTemplatedEmail(any(), any(), any(), any());
        } finally {
            delivery.stop();
        }
    }

    @Test
    void aRequestTheProviderRejectsAsAWholeIsRetriedNotRefused() {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        RecipientDelivery delivery = new RecipientDelivery(claims, provider, timeouts(Duration.ofMinutes(5)),
                new SimpleMeterRegistry(), new EmailCopies(""));
        RecipientClaims.Claim claim = new RecipientClaims.Claim(1, OffsetDateTime.now(), System.nanoTime(), false);
        when(claims.lease()).thenReturn(Duration.ofMinutes(5));
        when(claims.claim(any(), any(), any(), any(), any())).thenReturn(new RecipientClaims.Claimed(claim));
        HttpResponse badRequest = mock(HttpResponse.class);
        when(badRequest.getStatusCode()).thenReturn(400);
        doThrow(new HttpResponseException("sender domain not verified", badRequest))
                .when(provider).sendTemplatedEmail(any(), any(), any(), any());

        try {
            assertThatThrownBy(() -> delivery.deliver(event("acs-400"), List.of("member@example.com"), "template",
                    "subject", Map.of(), "{}"))
                    .isInstanceOf(RetryableNotificationException.class);
            verify(claims, never()).markFailed(claim, "PERMANENT_FAILURE");
        } finally {
            delivery.stop();
        }
    }

    @Test
    void anAddressThatCannotBeSentToIsRefusedWithoutAskingTheProvider() {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        RecipientDelivery delivery = new RecipientDelivery(claims, provider, timeouts(Duration.ofMinutes(5)),
                new SimpleMeterRegistry(), new EmailCopies(""));
        RecipientClaims.Claim claim = new RecipientClaims.Claim(1, OffsetDateTime.now(), System.nanoTime(), false);
        when(claims.lease()).thenReturn(Duration.ofMinutes(5));
        when(claims.claim(any(), any(), any(), any(), any())).thenReturn(new RecipientClaims.Claimed(claim));
        when(claims.markFailed(claim, "PERMANENT_FAILURE")).thenReturn(true);

        try {
            assertThatThrownBy(() -> delivery.deliver(event("typo"), List.of("member@@example"), "template",
                    "subject", Map.of(), "{}"))
                    .isInstanceOf(RecipientsRefusedException.class);
            verify(provider, never()).sendTemplatedEmail(any(), any(), any(), any());
        } finally {
            delivery.stop();
        }
    }

    @Test
    void anEventStopsStartingSendsOnceItsBudgetIsSpent() {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        RecipientDelivery delivery = new RecipientDelivery(claims, provider, timeouts(Duration.ofMillis(400)),
                new SimpleMeterRegistry(), new EmailCopies(""));
        when(claims.lease()).thenReturn(Duration.ofMillis(400));
        when(claims.claim(any(), any(), any(), any(), any())).thenAnswer(invocation -> new RecipientClaims.Claimed(
                new RecipientClaims.Claim(1, OffsetDateTime.now(), System.nanoTime(), false)));
        when(claims.markDelivered(any())).thenReturn(true);
        doAnswer(invocation -> {
            Thread.sleep(150);
            return null;
        }).when(provider).sendTemplatedEmail(any(), any(), any(), any());

        try {
            assertThatThrownBy(() -> delivery.deliver(event("budget"), List.of("a@example.com", "b@example.com",
                    "c@example.com"), "template", "subject", Map.of(), "{}"))
                    .isInstanceOfSatisfying(RetryableNotificationException.class,
                            failure -> assertThat(failure.getReasonCode()).isEqualTo(RecipientDelivery.EVENT_BUDGET_SPENT));
            verify(provider, never()).sendTemplatedEmail(eq("c@example.com"), any(), any(), any());
        } finally {
            delivery.stop();
        }
    }

    private static DeliveryTimeouts timeouts(Duration lease) {
        return new DeliveryTimeouts("smtp", 100, 100, 100, Duration.ofMillis(10), lease);
    }

    private static NotificationEvent event(String requestId) {
        return NotificationEvent.builder().requestId(requestId)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();
    }
}
