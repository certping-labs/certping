// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.exception.CheckpointRecorder;
import com.certping.agent.exception.CheckpointRecorder.OrderOwner;
import com.certping.agent.exception.DuplicateDeliveryException;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Keeps, next to a certificate as {@code {xref}-attempt}, how far its current attempt has got once the CA may hold an
 * order for it: the order about to be sent (written before it is sent), the order sent, the result before it is sent,
 * and the attempt's end. A message delivered again (its retry or its result was sent but it was not settled, or its
 * pod stopped mid-flight) resumes from the record instead of ordering again; a finished attempt only sends its result
 * again, and a failed one does nothing.
 *
 * <p>The record names its attempt by the message type and {@link ScheduledRetryService#attemptKey}, so a later
 * command for the same certificate never resumes from it; that command's own record replaces it. There is at most one
 * per certificate. It is deleted with the certificate once its attempt's deadline has passed.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AttemptRecords {

    static final String NAME_SUFFIX = "-attempt";
    static final String UNREADABLE = "ATTEMPT_RECORD_UNREADABLE";
    /** How long past its attempt's deadline a record is kept, for a delivery already under way at the deadline. */
    static final Duration EXPIRY_MARGIN = Duration.ofDays(1);
    private static final Set<String> RECORDED_TYPES = Set.of("CERT_ISSUANCE", "CERT_RENEWAL", "CERT_MANUAL_DNS_VALIDATE");

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final ScheduledRetryService scheduledRetryService;
    private final Clock clock;

    /** One attempt's record: its latest checkpoint, or {@code failed} once it was dead-lettered. */
    record Entry(String messageType, String attemptKey, Map<String, String> checkpoint, boolean failed,
                 String expiresAt) {
    }

    /** Where a delivery picks its attempt up: ended for good, or from a checkpoint (none to start afresh). */
    public record Resume(boolean failed, Optional<IssuanceCheckpoint> checkpoint) {
    }

    /**
     * Where {@code message} picks its attempt up: the record of its attempt when that ended or is at least as far as
     * the message's own checkpoint, otherwise the message's own checkpoint.
     *
     * @throws RetryableAgentException when the record cannot be read right now
     * @throws PermanentAgentException when the record cannot be read at all; nothing is ordered blind
     */
    public Resume resume(InboundMessage message, String certificateXref) {
        Optional<IssuanceCheckpoint> own = IssuanceCheckpoint.fromMessage(message);
        Optional<Entry> entry;
        try {
            entry = ownEntry(message, certificateXref);
        } catch (TransientAgentException | RetryableAgentException e) {
            throw new RetryableAgentException(e.getErrorCode(),
                    "The attempt record of " + certificateXref + " cannot be read: " + e.getMessage(), null, e, null);
        }
        if (entry.isPresent() && entry.get().failed()) {
            return new Resume(true, Optional.empty());
        }
        Optional<IssuanceCheckpoint> recorded = entry.flatMap(AttemptRecords::checkpointOf);
        if (recorded.isEmpty() || own.isPresent() && own.get().step().ordinal() > recorded.get().step().ordinal()) {
            return new Resume(false, own);
        }
        log.info("Resuming xref={} from its recorded step {} (the message carries {})", certificateXref,
                recorded.get().step(), own.map(checkpoint -> checkpoint.step().name()).orElse("none"));
        return new Resume(false, recorded);
    }

    /**
     * Records the checkpoints of {@code message}'s attempt as its CA flow reaches them. {@code start} is the
     * checkpoint the delivery resumed from: an order about to be sent is refused as a duplicate delivery when the
     * record already holds another order of the attempt, which only a second delivery of it can have written.
     */
    public CheckpointRecorder recorder(InboundMessage message, String certificateXref,
                                       Optional<IssuanceCheckpoint> start) {
        return new DeliveryRecorder(message, certificateXref, start.orElse(null));
    }

    private final class DeliveryRecorder implements CheckpointRecorder {

        private final InboundMessage message;
        private final String certificateXref;
        private IssuanceCheckpoint last;
        private IssuanceCheckpoint beforeSending;

        DeliveryRecorder(InboundMessage message, String certificateXref, IssuanceCheckpoint start) {
            this.message = message;
            this.certificateXref = certificateXref;
            this.last = start;
        }

        @Override
        public void recordBeforeSending(IssuanceCheckpoint sending) {
            Optional<String> attemptKey = ScheduledRetryService.attemptKey(message);
            if (attemptKey.isEmpty() || !recorded(message, certificateXref)) {
                return;
            }
            requireNoOtherOrder(ownEntry(message, certificateXref));
            write(certificateXref, entry(message, attemptKey.get(), sending.toAppProperties(), false));
            beforeSending = last;
            last = sending;
        }

        @Override
        public void recordNotSent(IssuanceCheckpoint sending) {
            if (!sending.equals(last)) {
                return;
            }
            try {
                Optional<IssuanceCheckpoint> current = ownEntry(message, certificateXref)
                        .flatMap(AttemptRecords::checkpointOf);
                if (current.equals(Optional.of(sending))) {
                    if (beforeSending != null && beforeSending.pastBillableStep()) {
                        write(certificateXref, entry(message, ScheduledRetryService.attemptKey(message).orElseThrow(),
                                beforeSending.toAppProperties(), false));
                    } else {
                        secretStore.delete(secretStore.handleFor(name(certificateXref)));
                    }
                }
                last = beforeSending;
            } catch (RuntimeException e) {
                log.warn("Refused order of xref={} still recorded as sent; a redelivery looks it up: {}",
                        certificateXref, e.getMessage());
            }
        }

        @Override
        public void recordAnswered(IssuanceCheckpoint answered) {
            try {
                save(message, certificateXref, answered);
                last = answered;
            } catch (RuntimeException e) {
                log.warn("Order of xref={} at {} not recorded; a redelivery finds it from the order sent: {}",
                        certificateXref, answered.step(), e.getMessage());
            }
        }

        @Override
        public OrderOwner recordedOwner(Predicate<IssuanceCheckpoint> mine) {
            Optional<String> attemptKey = ScheduledRetryService.attemptKey(message);
            if (attemptKey.isEmpty() || !recorded(message, certificateXref)) {
                return OrderOwner.THIS_DELIVERY;
            }
            try {
                Optional<Entry> entry = read(certificateXref);
                if (entry.isEmpty()) {
                    return OrderOwner.THIS_DELIVERY;
                }
                if (!messageType(message).equals(entry.get().messageType())
                        || !attemptKey.get().equals(entry.get().attemptKey()) || entry.get().failed()) {
                    return OrderOwner.NO_ONE;
                }
                boolean another = checkpointOf(entry.get()).filter(recorded ->
                        recorded.step() == IssuanceCheckpoint.Step.KV_STORED
                                || recorded.reached(IssuanceCheckpoint.Step.ORDER_SENT) && !mine.test(recorded))
                        .isPresent();
                return another ? OrderOwner.ANOTHER_DELIVERY : OrderOwner.THIS_DELIVERY;
            } catch (RuntimeException e) {
                log.warn("Attempt record of xref={} unreadable; the order is still tracked as this delivery's: {}",
                        certificateXref, e.getMessage());
                return OrderOwner.THIS_DELIVERY;
            }
        }

        private void requireNoOtherOrder(Optional<Entry> current) {
            if (current.isEmpty()) {
                return;
            }
            if (current.get().failed()) {
                throw new DuplicateDeliveryException("The attempt of " + certificateXref + " already failed");
            }
            Optional<IssuanceCheckpoint> recordedOrder = checkpointOf(current.get())
                    .filter(checkpoint -> checkpoint.reached(IssuanceCheckpoint.Step.ORDER_SENT));
            if (recordedOrder.isPresent() && !recordedOrder.get().equals(last)) {
                throw new DuplicateDeliveryException("Another delivery of the attempt of " + certificateXref
                        + " already recorded order step " + recordedOrder.get().step() + "; this one sends none");
            }
        }
    }

    /**
     * Records {@code checkpoint} for {@code message}'s attempt once it is past the billable step. A stored result
     * replaces any record of the attempt; any other checkpoint never replaces an ended record or a further one.
     *
     * @throws RuntimeException the store's failure, for the caller to decide whether to go on without the record
     */
    public void save(InboundMessage message, String certificateXref, IssuanceCheckpoint checkpoint) {
        Optional<String> attemptKey = ScheduledRetryService.attemptKey(message);
        if (checkpoint == null || !checkpoint.pastBillableStep() || attemptKey.isEmpty()
                || !recorded(message, certificateXref)) {
            return;
        }
        if (checkpoint.step() != IssuanceCheckpoint.Step.KV_STORED) {
            Optional<Entry> current = ownEntry(message, certificateXref);
            if (current.isPresent() && (current.get().failed() || checkpointOf(current.get())
                    .filter(further -> further.step().ordinal() > checkpoint.step().ordinal()).isPresent())) {
                return;
            }
        }
        write(certificateXref, entry(message, attemptKey.get(), checkpoint.toAppProperties(), false));
    }

    /**
     * Marks {@code message}'s attempt failed as it is dead-lettered, so any further delivery of it settles and does
     * nothing. Best effort.
     */
    public void fail(InboundMessage message, String certificateXref) {
        Optional<String> attemptKey = ScheduledRetryService.attemptKey(message);
        if (attemptKey.isEmpty() || !recorded(message, certificateXref)) {
            return;
        }
        try {
            write(certificateXref, entry(message, attemptKey.get(), null, true));
        } catch (RuntimeException e) {
            log.warn("Attempt of xref={} not marked failed: {}", certificateXref, e.getMessage());
        }
    }

    /**
     * Deletes the record with the certificate once no delivery of its attempt can come any more: past the attempt's
     * deadline, after which a delivery starts no work. An earlier record is kept, as a delivery without it would order
     * again. Best effort.
     */
    public void delete(String certificateXref) {
        if (certificateXref == null || certificateXref.isBlank()) {
            return;
        }
        try {
            Optional<Entry> entry = read(certificateXref);
            if (entry.isEmpty()) {
                return;
            }
            Instant expiresAt = Instant.parse(entry.get().expiresAt());
            if (clock.instant().isBefore(expiresAt)) {
                log.info("Attempt record of xref={} kept until {}: a delivery of its attempt may still come",
                        certificateXref, expiresAt);
                return;
            }
            secretStore.delete(secretStore.handleFor(name(certificateXref)));
        } catch (RuntimeException e) {
            log.warn("Attempt record of xref={} not deleted: {}", certificateXref, e.getMessage());
        }
    }

    private Optional<Entry> ownEntry(InboundMessage message, String certificateXref) {
        Optional<String> attemptKey = ScheduledRetryService.attemptKey(message);
        if (attemptKey.isEmpty() || !recorded(message, certificateXref)) {
            return Optional.empty();
        }
        return read(certificateXref).filter(entry -> messageType(message).equals(entry.messageType())
                && attemptKey.get().equals(entry.attemptKey()));
    }

    private Optional<Entry> read(String certificateXref) {
        String json;
        try {
            json = secretStore.read(secretStore.handleFor(name(certificateXref)));
        } catch (PermanentAgentException e) {
            if (notFound(e)) {
                return Optional.empty();
            }
            throw e;
        }
        Entry entry;
        try {
            entry = objectMapper.readValue(json, Entry.class);
        } catch (JacksonException | IllegalArgumentException e) {
            throw unreadable(certificateXref, e.getMessage(), e);
        }
        if (entry == null || entry.messageType() == null || entry.attemptKey() == null || !parses(entry.expiresAt())
                || !entry.failed() && checkpointOf(entry).isEmpty()) {
            throw unreadable(certificateXref, "it names no attempt, no expiry or no step", null);
        }
        return Optional.of(entry);
    }

    private static PermanentAgentException unreadable(String certificateXref, String reason, Exception cause) {
        return new PermanentAgentException(UNREADABLE,
                "The attempt record of " + certificateXref + " is unreadable: " + reason, cause);
    }

    private Entry entry(InboundMessage message, String attemptKey, Map<String, String> checkpoint,
                        boolean failed) {
        return new Entry(messageType(message), attemptKey, checkpoint, failed,
                scheduledRetryService.attemptDeadline(message).plus(EXPIRY_MARGIN).toString());
    }

    private void write(String certificateXref, Entry entry) {
        try {
            secretStore.create(name(certificateXref), objectMapper.writeValueAsString(entry));
        } catch (JacksonException e) {
            throw new PermanentAgentException("SERIALIZATION_FAILED",
                    "Failed to serialize the attempt record: " + e.getMessage(), e);
        }
    }

    private static boolean parses(String instant) {
        try {
            return instant != null && Instant.parse(instant) != null;
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    private static Optional<IssuanceCheckpoint> checkpointOf(Entry entry) {
        return entry.checkpoint() == null ? Optional.empty() : IssuanceCheckpoint.fromProperties(entry.checkpoint());
    }

    private static boolean recorded(InboundMessage message, String certificateXref) {
        return certificateXref != null && !certificateXref.isBlank() && RECORDED_TYPES.contains(messageType(message));
    }

    private static String messageType(InboundMessage message) {
        return message == null ? "" : String.valueOf(message.getApplicationProperties().get("MessageType"));
    }

    private static String name(String certificateXref) {
        return certificateXref + NAME_SUFFIX;
    }

    private static boolean notFound(PermanentAgentException e) {
        return e.getErrorCode() != null && e.getErrorCode().endsWith("_SECRET_NOT_FOUND");
    }
}
