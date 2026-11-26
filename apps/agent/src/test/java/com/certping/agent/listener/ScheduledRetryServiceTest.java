// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.MessageBody;
import com.certping.agent.transport.TransportMessage;
import com.certping.agent.transport.InboundMessage;
import com.certping.agent.transport.InboundContext;
import com.certping.agent.transport.MessageSender;
import com.certping.agent.config.AgentProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScheduledRetryServiceTest {

    private static final RetryPolicy NO_JITTER = new RetryPolicy(
            8, Map.of(), 200, Duration.ofHours(48), Duration.ofHours(168), Duration.ofHours(96), Duration.ofHours(168),
            0,
            List.of(Duration.ofSeconds(30), Duration.ofMinutes(2), Duration.ofMinutes(10),
                    Duration.ofHours(1)));

    @Test
    void pickDelay_honorsRetryAfterUnderCap() {
        Duration d = ScheduledRetryService.pickDelay(
                Duration.ofHours(2), 0, NO_JITTER, NO_JITTER.hardCapFor(false));

        assertThat(d).isEqualTo(Duration.ofHours(2));
    }

    @Test
    void pickDelay_capsRetryAfterAtHardCap() {
        // New-order cap is 48h; upstream asks for 9 days → capped to 48h.
        assertThat(ScheduledRetryService.pickDelay(Duration.ofDays(9), 0, NO_JITTER, NO_JITTER.hardCapFor(false)))
                .isEqualTo(Duration.ofHours(48));

        // Renewal cap is 168h (7d); same 9-day ask → capped to 168h.
        assertThat(ScheduledRetryService.pickDelay(Duration.ofDays(9), 0, NO_JITTER, NO_JITTER.hardCapFor(true)))
                .isEqualTo(Duration.ofHours(168));
    }

    @Test
    void pickDelay_usesBlindBackoffCurveWhenRetryAfterNull() {
        assertThat(ScheduledRetryService.pickDelay(null, 0, NO_JITTER, NO_JITTER.hardCapFor(false)))
                .isEqualTo(Duration.ofSeconds(30));
        assertThat(ScheduledRetryService.pickDelay(null, 1, NO_JITTER, NO_JITTER.hardCapFor(false)))
                .isEqualTo(Duration.ofMinutes(2));
        // Beyond the curve clamps to the last entry (1h).
        assertThat(ScheduledRetryService.pickDelay(null, 50, NO_JITTER, NO_JITTER.hardCapFor(false)))
                .isEqualTo(Duration.ofHours(1));
    }

    @Test
    void pickDelay_jitterIsUpwardAndBounded() {
        RetryPolicy jittered = new RetryPolicy(8, Map.of(), 200, Duration.ofHours(48), Duration.ofHours(168),
                Duration.ofHours(96), Duration.ofHours(168), 10, List.of(Duration.ofSeconds(100)));

        for (int i = 0; i < 200; i++) {
            Duration d = ScheduledRetryService.pickDelay(null, 0, jittered, jittered.hardCapFor(false));
            // base 100s, +0..10% → [100s, 110s]; never shortened below base.
            assertThat(d.toSeconds()).isBetween(100L, 110L);
        }
    }

    @Test
    void currentRetryCount_parsesIntegerStringAndMissing() {
        assertThat(ScheduledRetryService.currentRetryCount(messageWith(Map.of("RetryCount", 3)))).isEqualTo(3);
        assertThat(ScheduledRetryService.currentRetryCount(messageWith(Map.of("RetryCount", "5")))).isEqualTo(5);
        assertThat(ScheduledRetryService.currentRetryCount(messageWith(Map.of()))).isZero();
        assertThat(ScheduledRetryService.currentRetryCount(messageWith(Map.of("RetryCount", "x")))).isZero();
    }

    @Test
    void retriesUsedUp_afterThreePropagationWaitsByDefault() {
        ScheduledRetryService service = newService(mock(MessageSender.class));

        assertThat(service.retriesUsedUp(messageWith(Map.of("RetryCount", 2, "RetryCount.DNS_PROPAGATION_PENDING", 2)),
                "DNS_PROPAGATION_PENDING")).isFalse();
        assertThat(service.retriesUsedUp(messageWith(Map.of("RetryCount", 4, "RetryCount.DNS_PROPAGATION_PENDING", 3)),
                "DNS_PROPAGATION_PENDING")).isTrue();
    }

    private static InboundMessage messageWith(Map<String, Object> props) {
        InboundMessage msg = mock(InboundMessage.class);
        when(msg.getApplicationProperties()).thenReturn(new HashMap<>(props));
        return msg;
    }

    // ── scheduleRetry — re-enqueue through the gateway ─────────────────────────

    private ScheduledRetryService newService(MessageSender sender) {
        when(sender.getEntityPath()).thenReturn("test-inbound");
        return new ScheduledRetryService(sender, new AgentProperties(), new SimpleMeterRegistry(), Clock.systemUTC());
    }

    @Test
    void scheduleRetry_clonesMessageIncrementsRetryCountAndCompletesOriginal() {
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService svc = newService(sender);

        InboundContext ctx = mock(InboundContext.class);
        InboundMessage original = mock(InboundMessage.class);
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("{\"requestId\":\"r1\"}"));
        Map<String, Object> origProps = new HashMap<>();
        origProps.put("MessageType", "CERT_ISSUANCE");
        origProps.put("RetryCount", 3);
        origProps.put("RetryCount.X_THROTTLED", 1);
        when(original.getApplicationProperties()).thenReturn(origProps);
        when(original.getCorrelationId()).thenReturn("corr-abc");

        boolean ok = svc.scheduleRetry(ctx, svc.slotFor(ctx.getMessage(), Duration.ofSeconds(60)).orElseThrow(), "X_THROTTLED", "rate limited");

        assertThat(ok).isTrue();
        verify(ctx, times(1)).complete();

        ArgumentCaptor<TransportMessage> sentCaptor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(sentCaptor.capture());
        TransportMessage sent = sentCaptor.getValue();
        assertThat(sent.getBody().toString()).isEqualTo("{\"requestId\":\"r1\"}");
        assertThat(sent.getCorrelationId()).isEqualTo("corr-abc");
        Map<String, Object> sentProps = sent.getApplicationProperties();
        assertThat(sentProps).containsEntry("MessageType", "CERT_ISSUANCE");
        assertThat(sentProps).containsEntry("RetryCount", 4);
        assertThat(sentProps).containsEntry("RetryCount.X_THROTTLED", 2);
        assertThat(sentProps).containsEntry("LastRetryReason", "X_THROTTLED");
        assertThat(sentProps).containsKey("LastRetryAt");
        assertThat(sentProps).containsEntry("LastRetryAfterSec", 60L);
        // ScheduledEnqueueTime must be set in the future (best-effort timing check).
        assertThat(sent.getScheduledEnqueueTime())
                .isAfter(OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(30));
    }

    @Test
    void scheduleRetry_missingRetryCount_startsAtOne() {
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService svc = newService(sender);

        InboundContext ctx = mock(InboundContext.class);
        InboundMessage original = mock(InboundMessage.class);
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("{}"));
        Map<String, Object> origProps = new HashMap<>();
        origProps.put("MessageType", "CERT_DEPLOYMENT");
        when(original.getApplicationProperties()).thenReturn(origProps);

        svc.scheduleRetry(ctx, svc.slotFor(ctx.getMessage(), Duration.ofSeconds(60)).orElseThrow(), "X", "y");

        ArgumentCaptor<TransportMessage> sentCaptor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(sentCaptor.capture());
        assertThat(sentCaptor.getValue().getApplicationProperties())
                .containsEntry("RetryCount", 1)
                .containsEntry("RetryCount.X", 1);
    }

    @Test
    void scheduleRetry_senderThrows_returnsFalseAndDoesNotComplete() {
        // Critical: when the send to the gateway fails we MUST NOT complete the original — losing
        // the message. Caller falls back to abandon() so it gets redelivered.
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService svc = newService(sender);

        InboundContext ctx = mock(InboundContext.class);
        InboundMessage original = mock(InboundMessage.class);
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("{}"));
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());
        doThrow(new RuntimeException("gateway unavailable")).when(sender).sendMessage(any());

        boolean ok = svc.scheduleRetry(ctx, svc.slotFor(ctx.getMessage(), Duration.ofSeconds(60)).orElseThrow(), "X", "y");

        assertThat(ok).isFalse();
        verify(ctx, never()).complete();
    }

    @Test
    void scheduleRetry_truncatesLongReasonMessage() {
        // The reason detail header gets truncated to 1KB so a giant exception message
        // doesn't blow the property-size limits.
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService svc = newService(sender);
        InboundContext ctx = mock(InboundContext.class);
        InboundMessage original = mock(InboundMessage.class);
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("{}"));
        when(original.getApplicationProperties()).thenReturn(new HashMap<>());
        String huge = "x".repeat(5000);

        svc.scheduleRetry(ctx, svc.slotFor(ctx.getMessage(), Duration.ofSeconds(1)).orElseThrow(), "X", huge);

        ArgumentCaptor<TransportMessage> sentCaptor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(sentCaptor.capture());
        String stored = (String) sentCaptor.getValue().getApplicationProperties().get("LastRetryReasonDetail");
        assertThat(stored).hasSize(1024);
    }
    // ── attempt age — bounded from the first copy's enqueue time ───────────────

    private static final Instant NOW = Instant.parse("2026-10-20T12:00:00Z");

    private ScheduledRetryService serviceAt(MessageSender sender, Instant now) {
        return new ScheduledRetryService(sender, new AgentProperties(), new SimpleMeterRegistry(),
                Clock.fixed(now, ZoneOffset.UTC));
    }

    private static InboundMessage enqueued(String messageType, Instant enqueuedAt, Map<String, Object> props) {
        InboundMessage message = mock(InboundMessage.class);
        Map<String, Object> all = new HashMap<>(props);
        all.put("MessageType", messageType);
        when(message.getApplicationProperties()).thenReturn(all);
        when(message.getEnqueuedTime()).thenReturn(OffsetDateTime.ofInstant(enqueuedAt, ZoneOffset.UTC));
        return message;
    }

    @Test
    void attemptKey_isTheFirstCopysOnEveryCopyAndNewForANewCommand() {
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService svc = serviceAt(sender, NOW);
        Instant firstEnqueued = NOW.minus(Duration.ofHours(1));
        InboundMessage original = enqueued("CERT_ISSUANCE", firstEnqueued, Map.of());
        when(original.getSequenceNumber()).thenReturn(42L);
        when(original.getBody()).thenReturn(MessageBody.fromString("{}"));
        InboundContext ctx = mock(InboundContext.class);
        when(ctx.getMessage()).thenReturn(original);

        svc.scheduleRetry(ctx, svc.slotFor(original, Duration.ofMinutes(15)).orElseThrow(), "ORDER_PENDING", "pending");

        ArgumentCaptor<TransportMessage> sent = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(sent.capture());
        assertThat(sent.getValue().getApplicationProperties()).containsEntry("OriginalSequenceNumber", 42L);
        InboundMessage copy = enqueued("CERT_ISSUANCE", NOW, sent.getValue().getApplicationProperties());
        when(copy.getSequenceNumber()).thenReturn(99L);
        InboundMessage nextCommand = enqueued("CERT_ISSUANCE", NOW, Map.of());
        when(nextCommand.getSequenceNumber()).thenReturn(43L);

        assertThat(ScheduledRetryService.attemptKey(original)).contains("42@" + firstEnqueued);
        assertThat(ScheduledRetryService.attemptKey(copy)).isEqualTo(ScheduledRetryService.attemptKey(original));
        assertThat(ScheduledRetryService.attemptKey(nextCommand)).contains("43@" + NOW);
    }

    @Test
    void attemptKey_ofACopyWithoutTheSequenceStampIsItsOwnAndOfAMessageWithoutAnEnqueueTimeIsNone() {
        InboundMessage olderCopy = enqueued("CERT_RENEWAL", NOW,
                Map.of(ScheduledRetryService.PROP_ORIGINAL_ENQUEUED_TIME, "2026-10-19T00:00:00Z"));
        when(olderCopy.getSequenceNumber()).thenReturn(7L);
        InboundMessage unstamped = mock(InboundMessage.class);
        when(unstamped.getApplicationProperties()).thenReturn(new HashMap<>());

        assertThat(ScheduledRetryService.attemptKey(olderCopy)).contains("7@2026-10-19T00:00:00Z");
        assertThat(ScheduledRetryService.attemptKey(unstamped)).isEmpty();
        assertThat(ScheduledRetryService.attemptKey(null)).isEmpty();
    }

    @Test
    void attemptDeadline_countsFromTheFirstCopysEnqueueTimeByKind() {
        ScheduledRetryService svc = serviceAt(mock(MessageSender.class), NOW);

        assertThat(svc.attemptDeadline(enqueued("CERT_ISSUANCE", NOW, Map.of())))
                .isEqualTo(NOW.plus(Duration.ofHours(96)));
        assertThat(svc.attemptDeadline(enqueued("CERT_RENEWAL", NOW, Map.of())))
                .isEqualTo(NOW.plus(Duration.ofHours(168)));
        assertThat(svc.attemptDeadline(enqueued("CERT_RENEWAL", NOW,
                Map.of("OriginalEnqueuedTime", NOW.minus(Duration.ofHours(100)).toString()))))
                .as("a copy's own enqueue time is when it was re-enqueued, not when the attempt began")
                .isEqualTo(NOW.plus(Duration.ofHours(68)));
    }

    @Test
    void attemptDeadline_anUnreadableStampFallsBackToTheCopysEnqueueTime() {
        ScheduledRetryService svc = serviceAt(mock(MessageSender.class), NOW);

        assertThat(svc.attemptDeadline(enqueued("CERT_ISSUANCE", NOW, Map.of("OriginalEnqueuedTime", "yesterday"))))
                .isEqualTo(NOW.plus(Duration.ofHours(96)));
    }

    @Test
    void slotFor_readsTheClockOnceAndLivesExactlyUntilTheDeadline() {
        ScheduledRetryService svc = serviceAt(mock(MessageSender.class), NOW);
        InboundMessage message = enqueued("CERT_ISSUANCE", NOW.minus(Duration.ofHours(90)), Map.of());

        ScheduledRetryService.RetrySlot slot = svc.slotFor(message, Duration.ofHours(5)).orElseThrow();

        assertThat(slot.scheduledFor()).isEqualTo(OffsetDateTime.ofInstant(NOW.plus(Duration.ofHours(5)), ZoneOffset.UTC));
        assertThat(slot.timeToLive()).isEqualTo(Duration.ofHours(1));
        assertThat(slot.scheduledFor().toInstant().plus(slot.timeToLive())).isEqualTo(svc.attemptDeadline(message));
    }

    @Test
    void slotFor_isEmptyWhenLessThanAMinuteOfTheDeadlineWouldBeLeft() {
        ScheduledRetryService svc = serviceAt(mock(MessageSender.class), NOW);
        InboundMessage message = enqueued("CERT_ISSUANCE", NOW.minus(Duration.ofHours(90)), Map.of());

        assertThat(svc.slotFor(message, Duration.ofHours(6).minusMinutes(1))).isPresent();
        assertThat(svc.slotFor(message, Duration.ofHours(6).minusSeconds(59))).isEmpty();
        assertThat(svc.slotFor(message, Duration.ofHours(7))).isEmpty();
    }

    @Test
    void requireTimeLeft_refusesWorkPastTheDeadline() {
        ScheduledRetryService svc = serviceAt(mock(MessageSender.class), NOW);
        InboundMessage overdue = enqueued("CERT_ISSUANCE", NOW.minus(Duration.ofHours(97)), Map.of());

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> svc.requireTimeLeft(overdue))
                .isInstanceOfSatisfying(com.certping.agent.exception.PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("ATTEMPT_DEADLINE_PASSED"));
        svc.requireTimeLeft(enqueued("CERT_ISSUANCE", NOW.minus(Duration.ofHours(95)), Map.of()));
    }

    @Test
    void theFullBlindBackoffCurveStaysInsideTheNewOrderBound() {
        AgentProperties.RetryProperties retry = new AgentProperties().getRetry();
        Duration curve = Duration.ZERO;
        RetryPolicy policy = RetryPolicy.from(retry);
        for (int i = 0; i < retry.getMaxScheduledRetries(); i++) {
            Duration step = policy.blindBackoffFor(i);
            curve = curve.plus(step).plus(step.multipliedBy(retry.getJitterPercent()).dividedBy(100));
        }

        assertThat(curve).isLessThan(retry.getMaxAttemptAgeNewOrder());
    }

    @Test
    void scheduleRetry_stampsTheFirstEnqueueTimeAndExpiresTheCopyAtTheDeadline() {
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService svc = serviceAt(sender, NOW);
        InboundContext ctx = mock(InboundContext.class);
        InboundMessage original = enqueued("CERT_RENEWAL", NOW.minus(Duration.ofHours(10)), Map.of());
        when(ctx.getMessage()).thenReturn(original);
        when(original.getBody()).thenReturn(MessageBody.fromString("{}"));

        assertThat(svc.scheduleRetry(ctx, svc.slotFor(ctx.getMessage(), Duration.ofHours(1)).orElseThrow(), "X", "x")).isTrue();

        ArgumentCaptor<TransportMessage> sent = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(sent.capture());
        assertThat(sent.getValue().getApplicationProperties())
                .containsEntry("OriginalEnqueuedTime", NOW.minus(Duration.ofHours(10)).toString());
        assertThat(sent.getValue().getScheduledEnqueueTime())
                .isEqualTo(OffsetDateTime.ofInstant(NOW.plus(Duration.ofHours(1)), ZoneOffset.UTC));
        assertThat(sent.getValue().getTimeToLive()).isEqualTo(Duration.ofHours(168 - 10 - 1));
    }

    @Test
    void scheduleRetry_keepsTheFirstEnqueueTimeOnLaterCopies() {
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService svc = serviceAt(sender, NOW);
        InboundContext ctx = mock(InboundContext.class);
        String first = NOW.minus(Duration.ofHours(50)).toString();
        InboundMessage copy = enqueued("CERT_ISSUANCE", NOW.minus(Duration.ofMinutes(1)),
                Map.of("OriginalEnqueuedTime", first));
        when(ctx.getMessage()).thenReturn(copy);
        when(copy.getBody()).thenReturn(MessageBody.fromString("{}"));

        svc.scheduleRetry(ctx, svc.slotFor(ctx.getMessage(), Duration.ofHours(1)).orElseThrow(), "X", "x");

        ArgumentCaptor<TransportMessage> sent = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(sent.capture());
        assertThat(sent.getValue().getApplicationProperties()).containsEntry("OriginalEnqueuedTime", first);
        assertThat(sent.getValue().getTimeToLive()).isEqualTo(Duration.ofHours(96 - 50 - 1));
    }
}
