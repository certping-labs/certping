// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.interceptor.RequestContextInterceptor;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.utils.RequestContextLogger;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PreDestroy;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.eclipse.angus.mail.smtp.SMTPAddressFailedException;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Sends a deliver-once event to each recipient at most once per claim: a recipient another consumer
 * has already sent it to is skipped, one whose send failed stays retryable, and the event is retried
 * until every recipient has it. A send is bounded well inside the claim's lease
 * ({@link DeliveryTimeouts}), so no second consumer can claim a recipient while a send to it may
 * still be under way; its completion is fenced on the claim, so a holder that lost the claim never
 * records over the new owner.
 *
 * <p>A recipient whose address is refused for good is given up on alone: the others still get the
 * email, and the event is reported as refused only once no recipient is left to retry.
 *
 * <p>One duplicate remains possible: the provider accepted the email and the consumer died, or
 * failed to record it, before marking the recipient delivered. The claim then lapses and the next
 * attempt sends again; that attempt is counted as {@value #LEASE_TAKEN_OVER_METRIC}.
 */
@Service
class RecipientDelivery {

    static final String SEND_FAILED = "RECIPIENT_SEND_FAILED";
    static final String CLAIMED_ELSEWHERE = "RECIPIENT_CLAIMED";
    static final String EVENT_BUDGET_SPENT = "EVENT_SEND_BUDGET_SPENT";
    static final String CLAIM_LOST_METRIC = "notification.delivery.claim_lost";
    static final String LEASE_TAKEN_OVER_METRIC = "notification.delivery.lease_taken_over";

    /** Long enough for a transient provider fault to clear, short enough to be well inside a day. */
    static final Duration SEND_RETRY_AFTER = Duration.ofMinutes(2);

    /** A held claim is looked at again just after it lapses. */
    private static final Duration AFTER_LEASE = Duration.ofSeconds(5);

    private static final int MAX_FAILURE_REASON_LENGTH = 1000;

    private final RecipientClaims claims;
    private final EmailProvider emailProvider;
    private final DeliveryTimeouts timeouts;
    private final MeterRegistry meterRegistry;
    private final EmailCopies emailCopies;
    private final ExecutorService sendExecutor = Executors.newVirtualThreadPerTaskExecutor();

    RecipientDelivery(RecipientClaims claims, EmailProvider emailProvider, DeliveryTimeouts timeouts,
                      MeterRegistry meterRegistry, EmailCopies emailCopies) {
        this.claims = claims;
        this.emailProvider = emailProvider;
        this.timeouts = timeouts;
        this.meterRegistry = meterRegistry;
        this.emailCopies = emailCopies;
    }


    @PreDestroy
    void stop() {
        sendExecutor.shutdownNow();
    }

    /**
     * Returns once every recipient that can receive the email has it. Throws
     * {@link RetryableNotificationException} while any recipient is left to retry, and
     * {@link RecipientsRefusedException} when none is but some refused it for good.
     */
    void deliver(NotificationEvent event, List<String> recipients, String templateName, String subject,
                 Map<String, Object> model, String payloadJson) {
        long started = System.nanoTime();
        Attempt attempt = new Attempt();
        // Copies ride on the carrier's message alone, so they share its claim and are sent at most once.
        List<String> copies = emailCopies.of(event, recipients);
        int carrier = EmailCopies.carrier(recipients);
        for (int i = 0; i < recipients.size(); i++) {
            String recipient = recipients.get(i);
            List<String> recipientCopies = i == carrier ? copies : List.of();
            if (!timeouts.canStartSend(Duration.ofNanos(System.nanoTime() - started))) {
                attempt.retry(new RetryableNotificationException(EVENT_BUDGET_SPENT,
                        "the event's send budget was spent before every recipient was tried", AFTER_LEASE));
                break;
            }
            switch (claims.claim(event, recipient, templateName, subject, payloadJson)) {
                case RecipientClaims.AlreadyDelivered delivered -> {
                }
                case RecipientClaims.Permanent permanent -> attempt.refused();
                case RecipientClaims.Held held -> attempt.heldUntil(held.leaseEnds());
                case RecipientClaims.Claimed claimed ->
                        attempt.add(send(recipient, recipientCopies, claimed.claim(), templateName, subject, model));
            }
        }
        attempt.finish();
    }

    private SendResult send(String recipient, List<String> copies, RecipientClaims.Claim claim, String templateName,
                            String subject, Map<String, Object> model) {
        if (claim.takenOver()) {
            meterRegistry.counter(LEASE_TAKEN_OVER_METRIC).increment();
        }
        if (!timeouts.fitsInLease(claims.lease(), Duration.ofNanos(System.nanoTime() - claim.claimedNanos()))) {
            return new Retry(new RetryableNotificationException(CLAIMED_ELSEWHERE,
                    "the claim lapsed before its send could start", AFTER_LEASE));
        }
        if (!isAddress(recipient)) {
            return refuse(claim);
        }
        try {
            sendWithinBudget(recipient, copies, templateName, subject, model);
        } catch (EmailSendDeadlineException overrun) {
            return new Retry(new RetryableNotificationException(SEND_FAILED, overrun.getMessage(),
                    retryAfterClaim(claim), overrun));
        } catch (RuntimeException failure) {
            return isRefusedAddress(failure) ? refuse(claim) : fail(claim, failure);
        }
        if (!claims.markDelivered(claim)) {
            claimLost(claim);
        }
        return new Sent();
    }

    /**
     * Sends on its own thread and waits at most the send budget; an overrun interrupts the send. The
     * claim is kept until its lease ends, since the provider may still have taken the email.
     */
    private void sendWithinBudget(String recipient, List<String> copies, String templateName, String subject,
                                  Map<String, Object> model) {
        Future<?> send = sendExecutor.submit(() -> EmailCopies.send(
                emailProvider, recipient, copies, subject, templateName, model));
        try {
            send.get(timeouts.sendBudget().toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            send.cancel(true);
            throw new EmailSendDeadlineException("email send exceeded its deadline");
        } catch (InterruptedException e) {
            send.cancel(true);
            Thread.currentThread().interrupt();
            throw new EmailSendDeadlineException("email send was interrupted");
        } catch (ExecutionException e) {
            throw e.getCause() instanceof RuntimeException failure
                    ? failure : new IllegalStateException("email send failed", e.getCause());
        }
    }

    private SendResult refuse(RecipientClaims.Claim claim) {
        if (!claims.markFailed(claim, UndeliveredEmailService.PERMANENT_FAILURE)) {
            claimLost(claim);
        }
        return new Refused();
    }

    private SendResult fail(RecipientClaims.Claim claim, RuntimeException failure) {
        RetryableNotificationException retry = failure instanceof RetryableNotificationException retryable
                ? retryable : new RetryableNotificationException(SEND_FAILED, failure.getMessage(), SEND_RETRY_AFTER, failure);
        if (!claims.markFailed(claim, reason(retry))) {
            claimLost(claim);
        }
        return new Retry(retry);
    }

    /** An address that cannot be sent to at all is refused before any provider is asked. */
    private static boolean isAddress(String recipient) {
        try {
            new InternetAddress(recipient, true).validate();
            return true;
        } catch (AddressException e) {
            return false;
        }
    }

    /**
     * The receiving server refused this recipient for good. Anything else, a provider rejecting the
     * request as a whole included, may be our own misconfiguration and is retried.
     */
    private static boolean isRefusedAddress(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof SMTPAddressFailedException address
                    && address.getReturnCode() >= 500 && address.getReturnCode() < 600) {
                return true;
            }
        }
        return false;
    }

    private void claimLost(RecipientClaims.Claim claim) {
        meterRegistry.counter(CLAIM_LOST_METRIC).increment();
        contextLogger().warn("recipient record {} was claimed by another consumer before this one recorded its send",
                claim.id());
    }

    private static String reason(RetryableNotificationException e) {
        String reason = e.getReasonCode() + ": " + e.getMessage();
        return reason.length() <= MAX_FAILURE_REASON_LENGTH ? reason : reason.substring(0, MAX_FAILURE_REASON_LENGTH);
    }

    private Duration retryAfterClaim(RecipientClaims.Claim claim) {
        Duration remaining = Duration.between(OffsetDateTime.now(ZoneOffset.UTC), claim.claimedAt().plus(claims.lease()));
        return remaining.isNegative() ? AFTER_LEASE : remaining.plus(AFTER_LEASE);
    }

    private Logger contextLogger() {
        return RequestContextLogger.getLogger(RecipientDelivery.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }

    private sealed interface SendResult permits Sent, Retry, Refused {
    }

    private record Sent() implements SendResult {
    }

    private record Retry(RetryableNotificationException failure) implements SendResult {
    }

    private record Refused() implements SendResult {
    }

    /** What one pass over the recipients left: the latest retry needed, a held claim, refusals. */
    private static final class Attempt {

        private RetryableNotificationException retry;
        private OffsetDateTime heldUntil;
        private int refused;

        void add(SendResult result) {
            switch (result) {
                case Sent sent -> {
                }
                case Retry needed -> retry(needed.failure());
                case Refused refusal -> refused();
            }
        }

        void retry(RetryableNotificationException failure) {
            if (retry == null || failure.getRetryAfter().compareTo(retry.getRetryAfter()) > 0) {
                retry = failure;
            }
        }

        void refused() {
            refused++;
        }

        void heldUntil(OffsetDateTime leaseEnds) {
            if (heldUntil == null || leaseEnds.isBefore(heldUntil)) {
                heldUntil = leaseEnds;
            }
        }

        void finish() {
            if (retry != null) {
                throw retry;
            }
            if (heldUntil != null) {
                Duration wait = Duration.between(OffsetDateTime.now(ZoneOffset.UTC), heldUntil).plus(AFTER_LEASE);
                throw new RetryableNotificationException(CLAIMED_ELSEWHERE,
                        "another consumer holds a recipient of this email", wait.isNegative() ? AFTER_LEASE : wait);
            }
            if (refused > 0) {
                throw new RecipientsRefusedException(refused);
            }
        }
    }
}
