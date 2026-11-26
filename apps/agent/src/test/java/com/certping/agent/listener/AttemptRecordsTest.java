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
import com.certping.agent.secrets.InMemorySecretStore;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AttemptRecordsTest {

    private static final String XREF = "cert-1";
    private static final String RECORD = XREF + "-attempt";
    private static final Instant ENQUEUED = Instant.parse("2026-10-20T10:00:00Z");
    private static final IssuanceCheckpoint SENT = new IssuanceCheckpoint("DIGICERT",
            IssuanceCheckpoint.Step.ORDER_SENT, null, null, "kv-staged").withDcv("{\"hash\":\"a\"}", ENQUEUED);
    private static final IssuanceCheckpoint ORDERED =
            new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED, "999", null, "kv-staged");

    private final InMemorySecretStore store = new InMemorySecretStore();
    private final AttemptRecords records = TestAttemptRecords.over(store);

    @Test
    void aRedeliveryWithoutACheckpointResumesFromItsAttemptsRecord() {
        records.save(delivery("CERT_ISSUANCE", 42, null), XREF, ORDERED);

        AttemptRecords.Resume resume = records.resume(delivery("CERT_ISSUANCE", 42, null), XREF);

        assertThat(resume.failed()).isFalse();
        assertThat(resume.checkpoint()).contains(ORDERED);
    }

    @Test
    void aRedeliveryWithAnOlderCheckpointResumesFromTheRecordAndAFurtherOneKeepsItsOwn() {
        records.save(delivery("CERT_RENEWAL", 42, null), XREF, ORDERED);

        assertThat(records.resume(delivery("CERT_RENEWAL", 42, SENT), XREF).checkpoint())
                .contains(ORDERED);
        IssuanceCheckpoint finalized = ORDERED.withStep(IssuanceCheckpoint.Step.ORDER_FINALIZED);
        assertThat(records.resume(delivery("CERT_RENEWAL", 42, finalized), XREF).checkpoint()).contains(finalized);
    }

    @Test
    void anotherCommandForTheSameCertificateNeverResumesFromTheRecord() {
        records.save(delivery("CERT_RENEWAL", 42, null), XREF, ORDERED);
        records.fail(delivery("CERT_ISSUANCE", 7, null), "cert-2");

        assertThat(records.resume(delivery("CERT_RENEWAL", 43, null), XREF).checkpoint()).isEmpty();
        assertThat(records.resume(message("CERT_RENEWAL", 42, ENQUEUED.plusSeconds(1), Map.of()), XREF)
                .checkpoint()).isEmpty();
        assertThat(records.resume(delivery("CERT_ISSUANCE", 42, null), XREF).checkpoint()).isEmpty();
        assertThat(records.resume(delivery("CERT_RENEWAL", 42, null), "cert-3").checkpoint()).isEmpty();
        assertThat(records.resume(delivery("CERT_ISSUANCE", 8, null), "cert-2").failed()).isFalse();
    }

    @Test
    void aRetryCopyOfTheAttemptResumesFromItsRecord() {
        records.save(delivery("CERT_ISSUANCE", 42, null), XREF, ORDERED);
        InboundMessage copy = message("CERT_ISSUANCE", 99, ENQUEUED.plusSeconds(900), Map.of(
                ScheduledRetryService.PROP_ORIGINAL_SEQUENCE_NUMBER, 42L,
                ScheduledRetryService.PROP_ORIGINAL_ENQUEUED_TIME, ENQUEUED.toString()));

        assertThat(records.resume(copy, XREF).checkpoint()).contains(ORDERED);
    }

    @Test
    void aFailedAttemptIsReportedEndedToEveryDeliveryOfIt() {
        records.save(delivery("CERT_ISSUANCE", 42, null), XREF, ORDERED);

        records.fail(delivery("CERT_ISSUANCE", 42, null), XREF);

        AttemptRecords.Resume resume = records.resume(delivery("CERT_ISSUANCE", 42, SENT), XREF);
        assertThat(resume.failed()).isTrue();
        assertThat(resume.checkpoint()).isEmpty();
    }

    @Test
    void nothingIsRecordedBeforeTheCaMayHoldAnOrder() {
        records.save(delivery("CERT_ISSUANCE", 42, null), XREF,
                new IssuanceCheckpoint("LETS_ENCRYPT", IssuanceCheckpoint.Step.CSR_GENERATED, null, null, "kv"));
        records.save(delivery("CERT_ISSUANCE", 42, null), XREF, null);
        records.save(delivery("CERT_DEPLOYMENT", 42, null), XREF, ORDERED);

        assertThat(store.contains(RECORD)).isFalse();
    }

    @Test
    void anOrderAtAnyCaASentOrderAndAStoredResultAreRecorded() {
        records.save(delivery("CERT_ISSUANCE", 1, null), "cert-le",
                new IssuanceCheckpoint("LETS_ENCRYPT", IssuanceCheckpoint.Step.ORDER_CREATED, "u", "a", "kv"));
        records.save(delivery("CERT_ISSUANCE", 2, null), "cert-digicert",
                new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED, "7", null, "kv"));
        records.save(delivery("CERT_ISSUANCE", 3, null), "cert-sent", SENT);
        records.save(delivery("CERT_MANUAL_DNS_VALIDATE", 4, null), "cert-manual",
                IssuanceCheckpoint.storedResult("LETS_ENCRYPT", "{}"));

        assertThat(store.contains("cert-le-attempt")).isTrue();
        assertThat(store.contains("cert-digicert-attempt")).isTrue();
        assertThat(store.contains("cert-sent-attempt")).isTrue();
        assertThat(store.contains("cert-manual-attempt")).isTrue();
    }

    @Test
    void anOlderCheckpointNeverReplacesAFurtherRecordAndNothingButAResultReplacesAFailedOne() {
        InboundMessage delivery = delivery("CERT_ISSUANCE", 42, null);
        records.save(delivery, XREF, ORDERED);
        records.save(delivery, XREF, SENT);
        assertThat(records.resume(delivery, XREF).checkpoint()).contains(ORDERED);

        records.fail(delivery, XREF);
        records.save(delivery, XREF, ORDERED);
        assertThat(records.resume(delivery, XREF).failed()).isTrue();

        records.save(delivery, XREF, IssuanceCheckpoint.storedResult("DIGICERT", "{\"r\":1}"));
        assertThat(records.resume(delivery, XREF).checkpoint().orElseThrow().response()).isEqualTo("{\"r\":1}");
    }

    @Test
    void aRecordThatCannotBeReadRightNowIsRetriedWithoutOrdering() {
        SecretStore failing = mock(SecretStore.class);
        when(failing.handleFor(anyString())).thenReturn("https://kv.vault.azure.net/secrets/" + RECORD);
        when(failing.read(anyString())).thenThrow(new TransientAgentException("KV_READ_FAILED", "busy"));

        assertThatThrownBy(() -> TestAttemptRecords.over(failing)
                .resume(delivery("CERT_ISSUANCE", 42, SENT), XREF))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo("KV_READ_FAILED");
                    assertThat(e.getCheckpoint()).isNull();
                });
    }

    @Test
    void aRecordRefusedOrUnreadableFailsTheDeliveryInsteadOfStartingAfresh() {
        SecretStore refusing = mock(SecretStore.class);
        when(refusing.handleFor(anyString())).thenReturn("https://kv.vault.azure.net/secrets/" + RECORD);
        when(refusing.read(anyString())).thenThrow(new PermanentAgentException("KV_ACCESS_DENIED", "denied"));

        assertThatThrownBy(() -> TestAttemptRecords.over(refusing)
                .resume(delivery("CERT_ISSUANCE", 42, null), XREF))
                .isInstanceOf(PermanentAgentException.class);
        for (String unreadable : new String[]{"not json", "null", "{\"messageType\":\"CERT_ISSUANCE\"}",
                "{\"messageType\":\"CERT_ISSUANCE\",\"attemptKey\":\"42@" + ENQUEUED + "\",\"checkpoint\":{}}"}) {
            store.create(RECORD, unreadable);
            assertThatThrownBy(() -> records.resume(delivery("CERT_ISSUANCE", 42, null), XREF))
                    .isInstanceOfSatisfying(PermanentAgentException.class,
                            e -> assertThat(e.getErrorCode()).isEqualTo(AttemptRecords.UNREADABLE));
        }
    }

    @Test
    void anOrderAboutToBeSentIsRecordedFirstAndItsAnswerAfter() {
        InboundMessage delivery = delivery("CERT_ISSUANCE", 42, null);
        CheckpointRecorder recorder = records.recorder(delivery, XREF, Optional.empty());

        recorder.recordBeforeSending(SENT);
        assertThat(records.resume(delivery, XREF).checkpoint()).contains(SENT);

        recorder.recordAnswered(ORDERED);
        assertThat(records.resume(delivery, XREF).checkpoint()).contains(ORDERED);
    }

    @Test
    void anOrderIsRefusedAsADuplicateDeliveryWhenAnotherDeliveryOfTheAttemptAlreadyRecordedOne() {
        InboundMessage first = delivery("CERT_ISSUANCE", 42, null);
        records.recorder(first, XREF, Optional.empty()).recordBeforeSending(SENT);
        IssuanceCheckpoint secondOrder = SENT.withDcv("{\"hash\":\"b\"}", ENQUEUED.plusSeconds(5));

        assertThatThrownBy(() -> records.recorder(delivery("CERT_ISSUANCE", 42, null), XREF, Optional.empty())
                .recordBeforeSending(secondOrder))
                .isInstanceOf(DuplicateDeliveryException.class);
        assertThat(records.resume(first, XREF).checkpoint()).contains(SENT);
    }

    @Test
    void aDeliveryThatResumedFromTheRecordedOrderMayRecordItsNextSend() {
        IssuanceCheckpoint replacementSent = SENT.withOrderAction(
                com.certping.agent.ssl.CaOrderAction.REPLACEMENT);
        InboundMessage delivery = delivery("CERT_RENEWAL", 42, null);
        records.save(delivery, XREF, replacementSent);
        IssuanceCheckpoint resent = replacementSent.withDcv("{\"hash\":\"a\",\"uniqueValue\":\"u\"}", ENQUEUED);

        records.recorder(delivery, XREF, Optional.of(replacementSent)).recordBeforeSending(resent);

        assertThat(records.resume(delivery, XREF).checkpoint()).contains(resent);
    }

    @Test
    void anOrderIsNotSentForAFailedAttemptOrWhenItCannotBeRecorded() {
        InboundMessage delivery = delivery("CERT_ISSUANCE", 42, null);
        records.fail(delivery, XREF);
        assertThatThrownBy(() -> records.recorder(delivery, XREF, Optional.empty()).recordBeforeSending(SENT))
                .isInstanceOf(DuplicateDeliveryException.class);

        SecretStore failing = mock(SecretStore.class);
        when(failing.handleFor(anyString())).thenReturn("https://kv.vault.azure.net/secrets/" + RECORD);
        when(failing.read(anyString())).thenThrow(new PermanentAgentException("KV_SECRET_NOT_FOUND", "none"));
        when(failing.create(anyString(), anyString())).thenThrow(new TransientAgentException("KV_WRITE_FAILED", "x"));
        assertThatThrownBy(() -> TestAttemptRecords.over(failing)
                .recorder(delivery("CERT_ISSUANCE", 43, null), XREF, Optional.empty())
                .recordBeforeSending(SENT))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void theRecordNamesTheOrdersOwner() {
        InboundMessage delivery = delivery("CERT_ISSUANCE", 42, null);
        CheckpointRecorder recorder = records.recorder(delivery, XREF, Optional.empty());

        assertThat(recorder.recordedOwner(recorded -> true)).isEqualTo(OrderOwner.THIS_DELIVERY);

        records.save(delivery, XREF, ORDERED);
        assertThat(recorder.recordedOwner(recorded -> true)).isEqualTo(OrderOwner.THIS_DELIVERY);
        assertThat(recorder.recordedOwner(recorded -> false)).isEqualTo(OrderOwner.ANOTHER_DELIVERY);

        records.save(delivery, XREF, IssuanceCheckpoint.storedResult("DIGICERT", "{}"));
        assertThat(recorder.recordedOwner(recorded -> true)).isEqualTo(OrderOwner.ANOTHER_DELIVERY);

        records.fail(delivery, XREF);
        assertThat(recorder.recordedOwner(recorded -> true)).isEqualTo(OrderOwner.NO_ONE);

        records.save(delivery("CERT_ISSUANCE", 43, null), XREF, ORDERED);
        assertThat(recorder.recordedOwner(recorded -> true)).isEqualTo(OrderOwner.NO_ONE);

        store.create(RECORD, "{not json");
        assertThat(recorder.recordedOwner(recorded -> false)).isEqualTo(OrderOwner.THIS_DELIVERY);
    }

    @Test
    void anOrderTheCaRefusedIsUnrecordedSoARedeliveryStartsWhereThisOneDid() {
        InboundMessage delivery = delivery("CERT_ISSUANCE", 42, null);
        CheckpointRecorder recorder = records.recorder(delivery, XREF, Optional.empty());
        recorder.recordBeforeSending(SENT);

        recorder.recordNotSent(SENT);

        assertThat(store.contains(RECORD)).isFalse();
    }

    @Test
    void aRefusedOrderAfterARefusedReplacementLeavesTheReplacementRecorded() {
        IssuanceCheckpoint replacementSent = SENT.withOrderAction(
                com.certping.agent.ssl.CaOrderAction.REPLACEMENT);
        InboundMessage delivery = delivery("CERT_RENEWAL", 42, null);
        CheckpointRecorder recorder = records.recorder(delivery, XREF, Optional.empty());
        recorder.recordBeforeSending(replacementSent);
        IssuanceCheckpoint orderSent = SENT.withDcv("{\"hash\":\"a\"}", ENQUEUED.plusSeconds(1));
        recorder.recordBeforeSending(orderSent);

        recorder.recordNotSent(orderSent);

        assertThat(records.resume(delivery, XREF).checkpoint()).contains(replacementSent);
    }

    @Test
    void anAnswerThatCannotBeRecordedIsLeftToTheRecordWrittenBeforeSending() {
        SecretStore failing = mock(SecretStore.class);
        when(failing.handleFor(anyString())).thenReturn("https://kv.vault.azure.net/secrets/" + RECORD);
        when(failing.read(anyString())).thenThrow(new TransientAgentException("KV_READ_FAILED", "busy"));

        TestAttemptRecords.over(failing).recorder(delivery("CERT_ISSUANCE", 42, null), XREF,
                Optional.empty()).recordAnswered(ORDERED);

        verify(failing, never()).create(anyString(), anyString());
    }

    @Test
    void markingAFailedAttemptSwallowsAStoreFailure() {
        SecretStore failing = mock(SecretStore.class);
        when(failing.create(anyString(), anyString())).thenThrow(new TransientAgentException("KV_WRITE_FAILED", "x"));

        TestAttemptRecords.over(failing).fail(delivery("CERT_ISSUANCE", 42, null), XREF);

        verify(failing).create(anyString(), anyString());
    }

    @Test
    void deletingWithTheCertificateKeepsARecordWhoseAttemptMayStillBeDeliveredAndRemovesAnExpiredOne() {
        records.save(delivery("CERT_ISSUANCE", 42, null), XREF, ORDERED);
        records.save(delivery("CERT_RENEWAL", 42, null), "cert-renewed", ORDERED);
        Instant issuanceExpiry = ENQUEUED.plus(Duration.ofHours(96)).plus(AttemptRecords.EXPIRY_MARGIN);
        Instant renewalExpiry = ENQUEUED.plus(Duration.ofHours(168)).plus(AttemptRecords.EXPIRY_MARGIN);

        TestAttemptRecords.over(store, Clock.fixed(issuanceExpiry.minusSeconds(1), ZoneOffset.UTC)).delete(XREF);
        assertThat(store.contains(RECORD)).isTrue();

        AttemptRecords afterIssuanceExpiry = TestAttemptRecords.over(store, Clock.fixed(issuanceExpiry, ZoneOffset.UTC));
        afterIssuanceExpiry.delete(XREF);
        afterIssuanceExpiry.delete("cert-renewed");
        afterIssuanceExpiry.delete(XREF);
        afterIssuanceExpiry.delete(null);
        assertThat(store.contains(RECORD)).isFalse();
        assertThat(store.contains("cert-renewed-attempt")).isTrue();

        TestAttemptRecords.over(store, Clock.fixed(renewalExpiry, ZoneOffset.UTC)).delete("cert-renewed");
        assertThat(store.contains("cert-renewed-attempt")).isFalse();
    }

    @Test
    void anUnreadableRecordIsNotDeletedWithTheCertificate() {
        store.create(RECORD, "{not json");

        TestAttemptRecords.over(store, Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC))
                .delete(XREF);

        assertThat(store.contains(RECORD)).isTrue();
    }

    private static InboundMessage delivery(String messageType, long sequenceNumber,
                                                      IssuanceCheckpoint checkpoint) {
        return message(messageType, sequenceNumber, ENQUEUED,
                checkpoint == null ? Map.of() : checkpoint.toAppProperties());
    }

    private static InboundMessage message(String messageType, long sequenceNumber, Instant enqueuedAt,
                                                     Map<String, ?> properties) {
        InboundMessage message = mock(InboundMessage.class);
        Map<String, Object> all = new HashMap<>(properties);
        all.put("MessageType", messageType);
        when(message.getApplicationProperties()).thenReturn(all);
        when(message.getSequenceNumber()).thenReturn(sequenceNumber);
        when(message.getEnqueuedTime()).thenReturn(OffsetDateTime.ofInstant(enqueuedAt, ZoneOffset.UTC));
        return message;
    }
}
