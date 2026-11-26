// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.listener.ScheduledRetryService;
import com.certping.agent.listener.TestAttemptRecords;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.enums.CertType;
import com.certping.agent.model.message.CertIssuanceMessage;
import com.certping.agent.model.message.CertIssuanceResponse;
import com.certping.agent.model.message.CertManualValidateMessage;
import com.certping.agent.model.message.CertRenewalMessage;
import com.certping.agent.secrets.InMemorySecretStore;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.SslIssuanceService;
import com.certping.agent.ssl.SslRenewalService;
import com.certping.agent.ssl.acme.LetsEncryptManualService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * A message delivered again (its result or a retry was sent but it was not settled, or its pod stopped mid-flight)
 * must order nothing: it sends the recorded result, resumes the recorded order, or settles a failed attempt. Every CA
 * and Akamai's external CSR go through the same processors.
 */
@ExtendWith(MockitoExtension.class)
class ResultRedeliveryTest {

    private static final String XREF = "xref-1";
    private static final Instant ENQUEUED = Instant.parse("2026-10-20T10:00:00Z");
    private static final String RECORD = XREF + "-attempt";

    @Mock private SslIssuanceService sslIssuanceService;
    @Mock private SslRenewalService sslRenewalService;
    @Mock private LetsEncryptManualService letsEncryptManualService;
    @Mock private ScheduledRetryService scheduledRetryService;
    @Mock private AgentMessageSender sender;

    private final InMemorySecretStore store = new InMemorySecretStore();
    private AttemptRecords records;
    private CertIssuanceProcessor issuance;
    private CertRenewalProcessor renewal;
    private CertManualIssuanceProcessor manual;

    @BeforeEach
    void setUp() {
        store.create(XREF, StoredResults.BUNDLE);
        ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
        records = TestAttemptRecords.over(store);
        StoredResultPublisher publisher = new StoredResultPublisher(sender, store, objectMapper,
                new SimpleMeterRegistry(), records);
        issuance = new CertIssuanceProcessor(sslIssuanceService, scheduledRetryService, publisher, records,
                Clock.systemUTC());
        renewal = new CertRenewalProcessor(sslRenewalService, scheduledRetryService, publisher, records,
                Clock.systemUTC());
        manual = new CertManualIssuanceProcessor(letsEncryptManualService, sender, publisher, records,
                scheduledRetryService, Clock.systemUTC());
    }

    static Stream<Arguments> issuancePaths() {
        return Stream.of(CaProvider.LETS_ENCRYPT, CaProvider.DIGICERT, CaProvider.GLOBALSIGN)
                .flatMap(ca -> Stream.of(Arguments.of(ca, null), Arguments.of(ca, "AKAMAI_CPS")));
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("issuancePaths")
    void issuance_redeliveredAfterItsResultWasSent_sendsItAgainWithoutIssuing(CaProvider ca, String specialCertType) {
        when(sslIssuanceService.issue(any())).thenReturn(storedCertificate());
        InboundMessage delivery = delivery("CERT_ISSUANCE", 42, ENQUEUED, Map.of());

        issuance.process(issuanceMessage(ca, specialCertType), unsettled(delivery));
        issuance.process(issuanceMessage(ca, specialCertType), settled(delivery));

        verify(sslIssuanceService, times(1)).issue(any());
        assertSentTwiceThenRecorded("ISSUED");
    }

    @ParameterizedTest
    @EnumSource(value = CaProvider.class, names = {"LETS_ENCRYPT", "DIGICERT", "GLOBALSIGN"})
    void renewal_redeliveredAfterItsResultWasSent_sendsItAgainWithoutRenewing(CaProvider ca) {
        when(sslRenewalService.renew(any())).thenReturn(storedCertificate());
        InboundMessage delivery = delivery("CERT_RENEWAL", 42, ENQUEUED, Map.of());

        renewal.process(renewalMessage(ca), unsettled(delivery));
        renewal.process(renewalMessage(ca), settled(delivery));

        verify(sslRenewalService, times(1)).renew(any());
        assertSentTwiceThenRecorded("RENEWED");
    }

    @Test
    void manualValidation_redeliveredAfterItsResultWasSent_sendsItAgainWithoutFinalizing() {
        when(letsEncryptManualService.completeValidation(anyString(), anyString(), anyString(), anyBoolean(),
                anyBoolean(), any(), anyString(), anyString(), any())).thenReturn(storedCertificate());
        InboundMessage delivery = delivery("CERT_MANUAL_DNS_VALIDATE", 42, ENQUEUED, Map.of());

        manual.processManualDnsValidation(validateMessage(), unsettled(delivery));
        manual.processManualDnsValidation(validateMessage(), settled(delivery));

        verify(letsEncryptManualService, times(1)).completeValidation(anyString(), anyString(), anyString(),
                anyBoolean(), anyBoolean(), any(), anyString(), anyString(), any());
        assertSentTwiceThenRecorded("ISSUED");
    }

    @Test
    void renewal_aLaterCommandForTheSameCertificateRenewsAgain() {
        when(sslRenewalService.renew(any())).thenReturn(storedCertificate());

        renewal.process(renewalMessage(CaProvider.DIGICERT),
                unsettled(delivery("CERT_RENEWAL", 42, ENQUEUED, Map.of())));
        renewal.process(renewalMessage(CaProvider.DIGICERT),
                settled(delivery("CERT_RENEWAL", 43, ENQUEUED.plusSeconds(86_400), Map.of())));

        verify(sslRenewalService, times(2)).renew(any());
        assertThat(store.get(RECORD)).contains("KV_STORED").contains("43@");
    }

    @Test
    void issuance_everyDeliveryOfAnAttemptCarriesTheSameAttemptKeyAndANewCommandAnother() {
        List<String> attemptKeys = new CopyOnWriteArrayList<>();
        when(sslIssuanceService.issue(any())).thenAnswer(invocation -> {
            attemptKeys.add(invocation.<CertIssuanceMessage>getArgument(0).getAttemptKey());
            throw new IllegalStateException("stopped before ordering");
        });

        for (InboundMessage delivery : List.of(delivery("CERT_ISSUANCE", 42, ENQUEUED, Map.of()),
                retryCopy(null), delivery("CERT_ISSUANCE", 43, ENQUEUED.plusSeconds(60), Map.of()))) {
            assertThatThrownBy(() -> issuance.process(issuanceMessage(CaProvider.DIGICERT, null), settled(delivery)))
                    .isInstanceOf(IllegalStateException.class);
        }

        assertThat(attemptKeys).hasSize(3).doesNotContainNull();
        assertThat(attemptKeys.get(1)).isEqualTo(attemptKeys.get(0));
        assertThat(attemptKeys.get(2)).isNotEqualTo(attemptKeys.get(0));
    }

    @Test
    void issuance_aRetryCopyFinishesFirstThenTheUnsettledOriginalOnlySendsItsResult() {
        when(sslIssuanceService.issue(any())).thenReturn(storedCertificate());
        InboundMessage original = delivery("CERT_ISSUANCE", 42, ENQUEUED, Map.of());
        InboundMessage copy = retryCopy(new IssuanceCheckpoint("DIGICERT",
                IssuanceCheckpoint.Step.ORDER_CREATED, "999", null, "kv-staged"));

        issuance.process(issuanceMessage(CaProvider.DIGICERT, null), settled(copy));
        issuance.process(issuanceMessage(CaProvider.DIGICERT, null), settled(original));

        verify(sslIssuanceService, times(1)).issue(any());
        assertSentTwiceThenRecorded("ISSUED");
    }

    @Test
    void issuance_aDeliveryOfAFailedAttemptSettlesAndOrdersNothing() {
        InboundMessage original = delivery("CERT_ISSUANCE", 42, ENQUEUED, Map.of());
        records.fail(retryCopy(null), XREF);
        InboundContext context = settled(original);

        issuance.process(issuanceMessage(CaProvider.DIGICERT, null), context);

        verify(context).complete();
        verifyNoInteractions(sslIssuanceService);
        verify(sender, never()).sendIssuanceResponse(any());
        verify(sender, never()).sendAgentError(any());
    }

    @Test
    void issuance_anUnreadableRecordOrdersNothing() {
        store.create(RECORD, "{not json");

        assertThatThrownBy(() -> issuance.process(issuanceMessage(CaProvider.DIGICERT, null),
                settled(delivery("CERT_ISSUANCE", 42, ENQUEUED, Map.of()))))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("ATTEMPT_RECORD_UNREADABLE"));
        verifyNoInteractions(sslIssuanceService);
    }

    @Test
    void issuance_aPodStoppedAfterTheOrderWasRecordedAndSent_isResumedFromTheSentOrder() {
        IssuanceCheckpoint sending = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_SENT, null,
                null, "kv-staged").withDcv("{\"hash\":\"h\"}", ENQUEUED);
        List<IssuanceCheckpoint> resumedFrom = new CopyOnWriteArrayList<>();
        when(sslIssuanceService.issue(any())).thenAnswer(invocation -> {
            CertIssuanceMessage message = invocation.getArgument(0);
            resumedFrom.add(message.getCheckpoint());
            if (message.getCheckpoint() == null) {
                message.getCheckpointRecorder().recordBeforeSending(sending);
                throw new IllegalStateException("pod stopped while the CA order was in flight");
            }
            return storedCertificate();
        });
        InboundMessage delivery = delivery("CERT_ISSUANCE", 42, ENQUEUED, Map.of());

        assertThatThrownBy(() -> issuance.process(issuanceMessage(CaProvider.DIGICERT, null), settled(delivery)))
                .isInstanceOf(IllegalStateException.class);
        issuance.process(issuanceMessage(CaProvider.DIGICERT, null), settled(delivery));

        assertThat(resumedFrom).hasSize(2);
        assertThat(resumedFrom.get(0)).isNull();
        assertThat(resumedFrom.get(1)).isEqualTo(sending);
    }

    @Test
    void twoDeliveriesOfOneAttemptAtOnce_bothResumeItsRecordedOrder() throws Exception {
        InboundMessage original = delivery("CERT_ISSUANCE", 42, ENQUEUED, Map.of());
        records.save(original, XREF,
                new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED, "999", null, "kv-staged"));
        InboundMessage copy = retryCopy(
                new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_SENT, null, null, "kv-staged"));
        InboundContext originalContext = settled(original);
        InboundContext copyContext = settled(copy);
        CyclicBarrier bothResuming = new CyclicBarrier(2);
        List<IssuanceCheckpoint> resumedFrom = new CopyOnWriteArrayList<>();
        when(sslIssuanceService.issue(any())).thenAnswer(invocation -> {
            resumedFrom.add(invocation.<CertIssuanceMessage>getArgument(0).getCheckpoint());
            bothResuming.await(10, TimeUnit.SECONDS);
            return storedCertificate();
        });

        ExecutorService deliveries = Executors.newFixedThreadPool(2);
        try {
            Future<?> first = deliveries.submit(() ->
                    issuance.process(issuanceMessage(CaProvider.DIGICERT, null), originalContext));
            Future<?> second = deliveries.submit(() ->
                    issuance.process(issuanceMessage(CaProvider.DIGICERT, null), copyContext));
            first.get(10, TimeUnit.SECONDS);
            second.get(10, TimeUnit.SECONDS);
        } finally {
            deliveries.shutdownNow();
        }

        assertThat(resumedFrom).hasSize(2).allSatisfy(checkpoint -> {
            assertThat(checkpoint.step()).isEqualTo(IssuanceCheckpoint.Step.ORDER_CREATED);
            assertThat(checkpoint.orderRef()).isEqualTo("999");
        });
    }

    private void assertSentTwiceThenRecorded(String status) {
        ArgumentCaptor<CertIssuanceResponse> sent = ArgumentCaptor.forClass(CertIssuanceResponse.class);
        verify(sender, times(2)).sendIssuanceResponse(sent.capture());
        assertThat(sent.getAllValues()).allSatisfy(response -> {
            assertThat(response.getCertificateXref()).isEqualTo(XREF);
            assertThat(response.getStatus()).isEqualTo(status);
            assertThat(response.getFingerprintSha256()).isEqualTo(StoredResults.fingerprint());
        });
        assertThat(store.get(RECORD)).contains("KV_STORED");
    }

    /** A retry copy of the first delivery (sequence 42), carrying {@code checkpoint}. */
    private static InboundMessage retryCopy(IssuanceCheckpoint checkpoint) {
        Map<String, Object> properties = new HashMap<>(checkpoint == null ? Map.of() : checkpoint.toAppProperties());
        properties.put(ScheduledRetryService.PROP_ORIGINAL_SEQUENCE_NUMBER, 42L);
        properties.put(ScheduledRetryService.PROP_ORIGINAL_ENQUEUED_TIME, ENQUEUED.toString());
        return delivery("CERT_ISSUANCE", 99, ENQUEUED.plusSeconds(900), properties);
    }

    private static IssuanceResult storedCertificate() {
        return new IssuanceResult(StoredResults.HANDLE, null, null, StoredResults.LEAF_SERIAL,
                StoredResults.fingerprint(), OffsetDateTime.now(), OffsetDateTime.now().plusDays(90), "CN=Issuer",
                null, "SHA256withECDSA", null, null, null, "EC", 256, null, null, null, null, null, CertType.DV);
    }

    private static InboundMessage delivery(String messageType, long sequenceNumber, Instant enqueuedAt,
                                                      Map<String, ?> properties) {
        InboundMessage message = mock(InboundMessage.class);
        Map<String, Object> all = new HashMap<>(properties);
        all.put("MessageType", messageType);
        when(message.getApplicationProperties()).thenReturn(all);
        lenient().when(message.getSequenceNumber()).thenReturn(sequenceNumber);
        lenient().when(message.getEnqueuedTime()).thenReturn(OffsetDateTime.ofInstant(enqueuedAt, ZoneOffset.UTC));
        return message;
    }

    private static InboundContext settled(InboundMessage message) {
        InboundContext context = mock(InboundContext.class);
        when(context.getMessage()).thenReturn(message);
        return context;
    }

    private static InboundContext unsettled(InboundMessage message) {
        InboundContext context = settled(message);
        doThrow(new IllegalStateException("lock lost")).when(context).complete();
        return context;
    }

    private static CertIssuanceMessage issuanceMessage(CaProvider ca, String specialCertType) {
        CertIssuanceMessage message = new CertIssuanceMessage();
        message.setRequestId("req-1");
        message.setOrganizationId("organization-1");
        message.setCertificateXref(XREF);
        message.setDomain("example.com");
        message.setCaProvider(ca);
        message.setSpecialCertType(specialCertType);
        return message;
    }

    private static CertRenewalMessage renewalMessage(CaProvider ca) {
        CertRenewalMessage message = new CertRenewalMessage();
        message.setRequestId("req-2");
        message.setOrganizationId("organization-1");
        message.setCertificateXref(XREF);
        message.setDomain("example.com");
        message.setCaProvider(ca);
        return message;
    }

    private static CertManualValidateMessage validateMessage() {
        CertManualValidateMessage message = new CertManualValidateMessage();
        message.setRequestId("req-3");
        message.setOrganizationId("organization-1");
        message.setCertificateXref(XREF);
        message.setDomain("example.com");
        message.setCaProvider(CaProvider.LETS_ENCRYPT);
        message.setAcmeOrderUrl("https://acme.test/order/1");
        message.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme-1");
        return message;
    }
}
