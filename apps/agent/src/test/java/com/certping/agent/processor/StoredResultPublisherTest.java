// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.transport.InboundContext;
import com.certping.agent.transport.DeadLetterOptions;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.listener.TestAttemptRecords;
import com.certping.agent.model.message.CertIssuanceResponse;
import com.certping.agent.secrets.InMemorySecretStore;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StoredResultPublisherTest {

    private static final String XREF = "xref-1";
    private static final String RECORD = XREF + "-attempt";

    @Mock private AgentMessageSender sender;
    @Mock private SecretStore secretStore;
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    @Mock private InboundContext context;

    private StoredResultPublisher publisher;

    @BeforeEach
    void setUp() {
        publisher = new StoredResultPublisher(sender, secretStore, JsonMapper.builderWithJackson2Defaults().build(), meters,
                TestAttemptRecords.over(secretStore));
    }

    @Test
    void aMessageWithoutAStoredResultIsLeftToTheProcessor() {
        assertThat(publisher.finishEnded(context, XREF, new AttemptRecords.Resume(false, Optional.empty()))).isFalse();

        verify(sender, never()).sendIssuanceResponse(any());
    }

    @Test
    void aStoredResultMatchingTheStoredCertificateIsSentAsStored() {
        StoredResults.deliverStored(context, StoredResults.storedResult(XREF));
        StoredResults.storeMatchingCertificate(secretStore);

        assertThat(publisher.finishEnded(context, XREF, carried())).isTrue();

        ArgumentCaptor<CertIssuanceResponse> sent = ArgumentCaptor.forClass(CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(sent.capture());
        assertThat(sent.getValue().getCertificateXref()).isEqualTo(XREF);
        assertThat(sent.getValue().getRequestId()).isEqualTo("req-1");
        assertThat(sent.getValue().getFingerprintSha256()).isEqualTo(StoredResults.fingerprint());
        verify(context).complete();
    }

    @Test
    void aResultForAnotherCertificateIsRefused() {
        StoredResults.deliverStored(context, StoredResults.storedResult("xref-2"));

        assertMismatch();
    }

    @Test
    void aResultPointingOutsideThisAgentsStoreIsRefused() {
        StoredResults.deliverStored(context, StoredResults.storedResult(XREF,
                "https://other.vault.azure.net/secrets/xref-1", StoredResults.fingerprint()));

        assertMismatch();
    }

    @Test
    void aResultWhoseFingerprintIsNotTheStoredCertificatesIsRefused() {
        StoredResults.deliverStored(context, StoredResults.storedResult(XREF, StoredResults.HANDLE, "AA:BB"));
        StoredResults.storeMatchingCertificate(secretStore);

        assertMismatch();
    }

    @Test
    void aStoredResultThatIsNotAResponseIsRefused() {
        StoredResults.deliverStored(context, "not json");

        assertMismatch();
    }

    @Test
    void whatTheCertificateSaysIsTakenFromTheStoredCertificateNotTheResult() {
        StoredResults.deliverStored(context, StoredResults.storedResult(XREF));
        StoredResults.storeMatchingCertificate(secretStore);

        publisher.finishEnded(context, XREF, carried());

        ArgumentCaptor<CertIssuanceResponse> sent = ArgumentCaptor.forClass(CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(sent.capture());
        assertThat(sent.getValue().getSerialNumber()).isEqualTo(StoredResults.LEAF_SERIAL);
        assertThat(sent.getValue().getValidFrom()).isNotNull();
        assertThat(sent.getValue().getValidTo()).isNotNull();
    }

    @Test
    void aStoredCertificateThatIsGoneIsRefused() {
        StoredResults.deliverStored(context, StoredResults.storedResult(XREF));
        when(secretStore.isOwnedByThisAgent(StoredResults.HANDLE)).thenReturn(true);
        when(secretStore.read(StoredResults.HANDLE))
                .thenThrow(new PermanentAgentException("KV_SECRET_NOT_FOUND", "gone"));

        assertMismatch();
    }

    @Test
    void aStoredStepWithoutAResultIsRefused() {
        StoredResults.deliverStored(context, null);

        assertMismatch();
    }

    @Test
    void aStoredBundleThatHoldsNoCertificateIsRefused() {
        StoredResults.deliverStored(context, StoredResults.storedResult(XREF));
        when(secretStore.isOwnedByThisAgent(StoredResults.HANDLE)).thenReturn(true);
        when(secretStore.read(StoredResults.HANDLE)).thenReturn("-----BEGIN PRIVATE KEY-----\nAAAA\n");

        assertMismatch();
    }

    @Test
    void aStoreThatCannotBeReadRightNowKeepsTheResult() {
        String stored = StoredResults.storedResult(XREF);
        StoredResults.deliverStored(context, stored);
        when(secretStore.isOwnedByThisAgent(StoredResults.HANDLE)).thenReturn(true);
        when(secretStore.read(StoredResults.HANDLE)).thenThrow(new TransientAgentException("KV_READ_FAILED", "busy"));

        assertThatThrownBy(() -> publisher.finishEnded(context, XREF, carried()))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo("KV_READ_FAILED");
                    assertThat(e.getCheckpoint().step()).isEqualTo(IssuanceCheckpoint.Step.KV_STORED);
                    assertThat(e.getCheckpoint().response()).isEqualTo(stored);
                });
        verify(sender, never()).sendIssuanceResponse(any());
    }

    @Test
    void aFailedSendKeepsTheResultForTheNextAttempt() {
        CertIssuanceResponse response = CertIssuanceResponse.builder().certificateXref(XREF).status("ISSUED").build();
        doThrow(new TransientAgentException("SEND_FAILED", "bus down")).when(sender).sendIssuanceResponse(response);

        assertThatThrownBy(() -> publisher.publish(response, context))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(StoredResultPublisher.PUBLISH_FAILED);
                    assertThat(e.getRetryAfter()).isNull();
                    assertThat(e.getCheckpoint().response()).contains("\"certificateXref\":\"xref-1\"");
                });
        verify(context, never()).complete();
    }

    @Test
    void aSendRefusedForGoodIsNotKept() {
        CertIssuanceResponse response = CertIssuanceResponse.builder().certificateXref(XREF).build();
        doThrow(new PermanentAgentException("OUTBOUND_ORGANIZATION_MISMATCH", "refused"))
                .when(sender).sendIssuanceResponse(response);

        assertThatThrownBy(() -> publisher.publish(response, context)).isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void aSentResultWhoseMessageCannotBeSettledIsNotSentAgainHere() {
        CertIssuanceResponse response = CertIssuanceResponse.builder().certificateXref(XREF).build();
        doThrow(new IllegalStateException("receiver disposed")).when(context).complete();

        publisher.publish(response, context);

        verify(sender).sendIssuanceResponse(response);
    }

    @Test
    void aNewResultIsRecordedBeforeItIsSentAndStaysRecordedOnceTheMessageIsSettled() {
        InMemorySecretStore store = new InMemorySecretStore();
        StoredResultPublisher recording = recordingPublisher(store);
        givenDelivery(context);
        doAnswer(invocation -> {
            assertThat(store.get(RECORD)).contains("KV_STORED").contains("xref-1");
            return null;
        }).when(sender).sendIssuanceResponse(any());

        recording.publish(response(), context);

        verify(sender).sendIssuanceResponse(any());
        verify(context).complete();
        assertThat(store.get(RECORD)).contains("KV_STORED");
    }

    @Test
    void aNewResultThatCannotBeRecordedIsNotSentAndIsKeptForTheNextAttempt() {
        givenDelivery(context);
        when(secretStore.create(eq(RECORD), anyString())).thenThrow(new TransientAgentException("KV_WRITE_FAILED", "busy"));

        assertThatThrownBy(() -> publisher.publish(response(), context))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(StoredResultPublisher.PUBLISH_FAILED);
                    assertThat(e.getCheckpoint().step()).isEqualTo(IssuanceCheckpoint.Step.KV_STORED);
                    assertThat(e.getCheckpoint().response()).contains("\"certificateXref\":\"xref-1\"");
                });
        verify(sender, never()).sendIssuanceResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void aSentResultWhoseMessageCannotBeSettledKeepsItsRecordForTheRedelivery() {
        InMemorySecretStore store = new InMemorySecretStore();
        givenDelivery(context);
        doThrow(new IllegalStateException("lock lost")).when(context).complete();

        recordingPublisher(store).publish(response(), context);

        assertThat(store.contains(RECORD)).isTrue();
    }

    @Test
    void aRecordedResultIsSentAgainAndStaysRecorded() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.create("xref-1", StoredResults.BUNDLE);
        StoredResultPublisher recording = recordingPublisher(store);
        givenDelivery(context);
        AttemptRecords records = TestAttemptRecords.over(store);
        records.save(context.getMessage(), XREF,
                IssuanceCheckpoint.storedResult("LETS_ENCRYPT", StoredResults.storedResult(XREF)));

        assertThat(recording.finishEnded(context, XREF, records.resume(context.getMessage(), XREF))).isTrue();

        verify(sender).sendIssuanceResponse(any());
        verify(context).complete();
        assertThat(store.get(RECORD)).contains("KV_STORED");
    }

    @Test
    void aRecordedResultThatDoesNotMatchTheStoredCertificateIsDeadLetteredAndItsAttemptMarkedFailed() {
        InMemorySecretStore store = new InMemorySecretStore();
        store.create("xref-1", StoredResults.BUNDLE);
        givenDelivery(context);
        AttemptRecords records = TestAttemptRecords.over(store);
        records.save(context.getMessage(), XREF, IssuanceCheckpoint.storedResult("LETS_ENCRYPT",
                StoredResults.storedResult(XREF, StoredResults.HANDLE, "AA:BB")));

        recordingPublisher(store).finishEnded(context, XREF, records.resume(context.getMessage(), XREF));

        verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(sender, never()).sendIssuanceResponse(any());
        assertThat(records.resume(context.getMessage(), XREF).failed()).isTrue();
    }

    @Test
    void aDeliveryOfAFailedAttemptIsSettledAndDoesNothing() {
        assertThat(publisher.finishEnded(context, XREF, new AttemptRecords.Resume(true, Optional.empty()))).isTrue();

        verify(context).complete();
        verify(sender, never()).sendIssuanceResponse(any());
        verify(sender, never()).sendAgentError(any());
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    private StoredResultPublisher recordingPublisher(InMemorySecretStore store) {
        return new StoredResultPublisher(sender, store, JsonMapper.builderWithJackson2Defaults().build(), meters,
                TestAttemptRecords.over(store));
    }

    private static CertIssuanceResponse response() {
        return CertIssuanceResponse.builder().certificateXref(XREF).status("ISSUED").build();
    }

    /** {@code context} delivers the first copy of a CERT_ISSUANCE command, with no checkpoint. */
    private static void givenDelivery(InboundContext context) {
        InboundMessage message = mock(InboundMessage.class);
        when(message.getApplicationProperties()).thenReturn(new HashMap<>(Map.of("MessageType", "CERT_ISSUANCE")));
        when(message.getSequenceNumber()).thenReturn(42L);
        when(message.getEnqueuedTime()).thenReturn(OffsetDateTime.parse("2026-10-20T10:00:00Z"));
        when(context.getMessage()).thenReturn(message);
    }

    private AttemptRecords.Resume carried() {
        return new AttemptRecords.Resume(false, IssuanceCheckpoint.fromMessage(context.getMessage()));
    }

    private void assertMismatch() {
        assertThat(publisher.finishEnded(context, XREF, carried())).isTrue();

        ArgumentCaptor<DeadLetterOptions> dlq = ArgumentCaptor.forClass(DeadLetterOptions.class);
        verify(context).deadLetter(dlq.capture());
        assertThat(dlq.getValue().getDeadLetterReason()).isEqualTo("RESPONSE_REPLAY_MISMATCH");
        assertThat(meters.counter("agent.response.replay.mismatch.count").count()).isEqualTo(1);
        verify(sender, never()).sendIssuanceResponse(any());
        verify(sender, never()).sendAgentError(any());
        verify(context, never()).complete();
    }
}
