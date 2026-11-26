// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.MessageBody;
import com.certping.notification.transport.TransportMessage;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.MessageSender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ScheduledRetryService}: the queue-level retry via
 * {@code ScheduledEnqueueTime}.
 */
@ExtendWith(MockitoExtension.class)
class ScheduledRetryServiceTest {

    @Mock private MessageSender senderClient;
    @Mock private InboundContext ctx;
    @Mock private InboundMessage original;

    private ScheduledRetryService service;

    @BeforeEach
    void setUp() {
        // maxScheduledRetries=3, hardCap=24h — matches production defaults
        service = new ScheduledRetryService(senderClient, 3, 24, Duration.ofDays(7));
    }

    // ── currentRetryCount ──────────────────────────────────────────────────

    @Test
    void currentRetryCount_missingProperty_returnsZero() {
        when(original.getApplicationProperties()).thenReturn(Map.of());
        assertThat(service.currentRetryCount(original)).isZero();
    }

    @Test
    void currentRetryCount_intValue_returned() {
        when(original.getApplicationProperties()).thenReturn(Map.of("RetryCount", 5));
        assertThat(service.currentRetryCount(original)).isEqualTo(5);
    }

    @Test
    void currentRetryCount_longValue_returnedAsInt() {
        when(original.getApplicationProperties()).thenReturn(Map.of("RetryCount", 7L));
        assertThat(service.currentRetryCount(original)).isEqualTo(7);
    }

    @Test
    void currentRetryCount_stringNumeric_parsed() {
        when(original.getApplicationProperties()).thenReturn(Map.of("RetryCount", "12"));
        assertThat(service.currentRetryCount(original)).isEqualTo(12);
    }

    @Test
    void currentRetryCount_stringUnparseable_returnsZero() {
        when(original.getApplicationProperties()).thenReturn(Map.of("RetryCount", "not-a-number"));
        assertThat(service.currentRetryCount(original)).isZero();
    }

    @Test
    void currentRetryCount_otherType_returnsZero() {
        when(original.getApplicationProperties()).thenReturn(Map.of("RetryCount", new Object()));
        assertThat(service.currentRetryCount(original)).isZero();
    }

    // ── scheduleRetry: refuse over max ─────────────────────────────────────

    @Test
    void scheduleRetry_wouldExceedMax_refusesAndReturnsFalse() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getApplicationProperties()).thenReturn(Map.of("RetryCount", 3)); // already at max

        boolean ok = service.scheduleRetry(ctx, Duration.ofSeconds(30), "ACS_RATE_LIMITED", "quota exceeded");

        assertThat(ok).isFalse();
        verify(senderClient, never()).sendMessage(any());
        verify(ctx, never()).complete();
    }

    // ── scheduleRetry: happy path (verbatim body) ──────────────────────────

    @Test
    void scheduleRetry_firstRetry_stampsPropertiesAndSchedulesFuture() {
        MessageBody body = MessageBody.fromString("[{\"foo\":\"bar\"}]");
        Map<String, Object> originalProps = new HashMap<>();
        originalProps.put("notificationType", "ACCOUNT_EVENT");
        originalProps.put("source", "cert-manager");
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(body);
        when(original.getApplicationProperties()).thenReturn(originalProps);
        when(original.getCorrelationId()).thenReturn("corr-1234");

        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);

        boolean ok = service.scheduleRetry(ctx, Duration.ofSeconds(60), "ACS_RATE_LIMITED", "quota");

        assertThat(ok).isTrue();
        ArgumentCaptor<TransportMessage> retryCaptor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(retryCaptor.capture());
        verify(ctx).complete();

        TransportMessage retry = retryCaptor.getValue();
        Map<String, Object> retryProps = retry.getApplicationProperties();
        assertThat(retryProps).containsEntry("RetryCount", 1);
        assertThat(retryProps).containsEntry("LastRetryReason", "ACS_RATE_LIMITED");
        assertThat(retryProps).containsEntry("LastRetryDetail", "quota");
        assertThat(retryProps).containsEntry("LastRetryAfterSec", 60L);
        // notificationType preserved — the listener routes each message to a handler by it
        assertThat(retryProps).containsEntry("notificationType", "ACCOUNT_EVENT");
        assertThat(retryProps).containsEntry("source", "cert-manager");
        assertThat(retryProps).containsKey("LastRetryAt");
        assertThat(retry.getCorrelationId()).isEqualTo("corr-1234");
        assertThat(retry.getScheduledEnqueueTime())
                .isAfterOrEqualTo(before.plus(59, ChronoUnit.SECONDS));
    }

    @Test
    void scheduleRetry_bumpsRetryCountFromExistingCount() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("[]"));
        when(original.getApplicationProperties()).thenReturn(new HashMap<>(Map.of("RetryCount", 2)));

        service.scheduleRetry(ctx, Duration.ofSeconds(15), "ACS_RATE_LIMITED", "still throttled");

        ArgumentCaptor<TransportMessage> retryCaptor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(retryCaptor.capture());
        assertThat(retryCaptor.getValue().getApplicationProperties()).containsEntry("RetryCount", 3);
    }

    // ── scheduleRetry: delay clamping ──────────────────────────────────────

    @Test
    void scheduleRetry_delayExceedsHardCap_clampedToCap() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("[]"));
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());

        // 48 hours — cap is 24 hours
        Duration wayTooLong = Duration.ofHours(48);
        service.scheduleRetry(ctx, wayTooLong, "ACS_RATE_LIMITED", "very slow");

        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(captor.capture());
        long clampedSec = (Long) captor.getValue().getApplicationProperties().get("LastRetryAfterSec");
        assertThat(clampedSec).isEqualTo(Duration.ofHours(24).toSeconds());
    }

    // ── scheduleRetry: replacement body variant ────────────────────────────

    @Test
    void scheduleRetry_replacementBody_usesReplacementNotOriginal() {
        when(ctx.getMessage()).thenReturn(original);
        // Original body has 3 events; retry body has just the 1 failed subset.
        Map<String, Object> originalProps = new HashMap<>();
        originalProps.put("notificationType", "SYSTEM_EVENT");
        when(original.getApplicationProperties()).thenReturn(originalProps);
        // original.getBody() should NOT be called when replacementBodyJson is provided

        String subset = "[{\"onlyFailedEvent\":true}]";
        service.scheduleRetry(ctx, Duration.ofSeconds(30), "ACS_RATE_LIMITED", "partial", subset);

        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getBody().toString()).isEqualTo(subset);
        // notificationType is still preserved onto the retry (routing critical)
        assertThat(captor.getValue().getApplicationProperties())
                .containsEntry("notificationType", "SYSTEM_EVENT");
    }

    // ── scheduleRetry: null-correlationId case ─────────────────────────────

    @Test
    void scheduleRetry_nullCorrelationId_notCopiedToRetry() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("[]"));
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());
        when(original.getCorrelationId()).thenReturn(null);

        service.scheduleRetry(ctx, Duration.ofSeconds(10), "R", "m");

        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getCorrelationId()).isNull();
    }

    // ── scheduleRetry: send failure ────────────────────────────────────────

    @Test
    void scheduleRetry_senderThrows_returnsFalseAndDoesNotComplete() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("[]"));
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());
        doThrow(new RuntimeException("bus down")).when(senderClient)
                .sendMessage(any(TransportMessage.class));

        boolean ok = service.scheduleRetry(ctx, Duration.ofSeconds(5), "R", "m");

        assertThat(ok).isFalse();
        verify(ctx, never()).complete();
    }

    // ── scheduleRetry: detail truncation ───────────────────────────────────

    @Test
    void scheduleRetry_veryLongDetail_truncatedToMax() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("[]"));
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());

        String longDetail = "x".repeat(1000);
        service.scheduleRetry(ctx, Duration.ofSeconds(5), "R", longDetail);

        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(captor.capture());
        assertThat((String) captor.getValue().getApplicationProperties().get("LastRetryDetail"))
                .hasSize(500);
    }

    @Test
    void scheduleRetry_nullDetail_becomesEmptyString() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("[]"));
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());

        service.scheduleRetry(ctx, Duration.ofSeconds(5), "R", null);

        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties()).containsEntry("LastRetryDetail", "");
    }

    // ── getMaxScheduledRetries ─────────────────────────────────────────────

    @Test
    void getMaxScheduledRetries_returnsConfiguredValue() {
        assertThat(service.getMaxScheduledRetries()).isEqualTo(3);
    }

    // ── scheduleRetries: deliver-once emails ───────────────────────────────

    @Test
    void untilDeliveredWithinBudget_stampsTheFirstRetryTime() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());

        List<ScheduledRetryService.Scheduled> outcome = service.scheduleRetries(ctx, List.of(untilDelivered()));

        assertThat(outcome).containsExactly(ScheduledRetryService.Scheduled.WITHIN_BUDGET);
        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties()).containsKey(ScheduledRetryService.PROP_FIRST_RETRY_AT);
        verify(ctx).complete();
    }

    @Test
    void untilDeliveredPastBudget_isRetriedHourly() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getApplicationProperties()).thenReturn(new HashMap<>(Map.of("RetryCount", 3,
                ScheduledRetryService.PROP_FIRST_RETRY_AT, java.time.Instant.now().minus(Duration.ofHours(2)).toString())));

        List<ScheduledRetryService.Scheduled> outcome = service.scheduleRetries(ctx, List.of(untilDelivered()));

        assertThat(outcome).containsExactly(ScheduledRetryService.Scheduled.PAST_BUDGET);
        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(senderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties())
                .containsEntry("LastRetryAfterSec", ScheduledRetryService.UNDELIVERED_EVERY.toSeconds())
                .containsEntry("RetryCount", 4);
        verify(ctx).complete();
    }

    @Test
    void untilDeliveredOlderThanItsMaximumAge_isRefused() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getApplicationProperties()).thenReturn(new HashMap<>(Map.of("RetryCount", 40,
                ScheduledRetryService.PROP_FIRST_RETRY_AT, java.time.Instant.now().minus(Duration.ofDays(8)).toString())));

        List<ScheduledRetryService.Scheduled> outcome = service.scheduleRetries(ctx, List.of(untilDelivered()));

        assertThat(outcome).containsExactly(ScheduledRetryService.Scheduled.REFUSED);
        verify(senderClient, never()).sendMessage(any());
        verify(ctx, never()).complete();
    }

    @Test
    void aStandardCopyBesideADeliverOnceCopyKeepsItsBudget() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getApplicationProperties()).thenReturn(new HashMap<>(Map.of("RetryCount", 3)));

        List<ScheduledRetryService.Scheduled> outcome = service.scheduleRetries(ctx, List.of(untilDelivered(),
                new ScheduledRetryService.RetryCopy(Duration.ofSeconds(30), "R", "m", "[]",
                        ScheduledRetryService.Policy.STANDARD)));

        assertThat(outcome).containsExactly(ScheduledRetryService.Scheduled.PAST_BUDGET,
                ScheduledRetryService.Scheduled.REFUSED);
        verify(ctx).complete();
        verify(senderClient, times(1)).sendMessage(any(TransportMessage.class));
    }

    @Test
    void aRefusedStandardCopyDoesNotBlockTheDeliverOnceCopy() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getApplicationProperties()).thenReturn(new HashMap<>(Map.of("RetryCount", 3)));

        List<ScheduledRetryService.Scheduled> outcomes = service.scheduleRetries(ctx, List.of(
                new ScheduledRetryService.RetryCopy(Duration.ofSeconds(30), "R", "m", "[]",
                        ScheduledRetryService.Policy.STANDARD), untilDelivered()));

        assertThat(outcomes).containsExactly(ScheduledRetryService.Scheduled.REFUSED,
                ScheduledRetryService.Scheduled.PAST_BUDGET);
        verify(senderClient, times(1)).sendMessage(any(TransportMessage.class));
        verify(ctx, times(1)).complete();
    }

    @Test
    void aFailedStandardCopyDoesNotScheduleTheDeliverOnceCopy() {
        when(ctx.getMessage()).thenReturn(original);
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());
        doThrow(new RuntimeException("bus down")).when(senderClient)
                .sendMessage(any(TransportMessage.class));

        List<ScheduledRetryService.Scheduled> outcomes = service.scheduleRetries(ctx, List.of(
                new ScheduledRetryService.RetryCopy(Duration.ofSeconds(30), "R", "m", "[]",
                        ScheduledRetryService.Policy.STANDARD), untilDelivered()));

        assertThat(outcomes).containsExactly(ScheduledRetryService.Scheduled.FAILED,
                ScheduledRetryService.Scheduled.FAILED);
        verify(senderClient, times(1)).sendMessage(any(TransportMessage.class));
        verify(ctx, never()).complete();
    }

    private static ScheduledRetryService.RetryCopy untilDelivered() {
        return new ScheduledRetryService.RetryCopy(Duration.ofMinutes(2), RecipientDelivery.SEND_FAILED, "m", "[]",
                ScheduledRetryService.Policy.UNTIL_DELIVERED);
    }
}
