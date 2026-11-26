// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.CaOrderPendingException;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.listener.ScheduledRetryService;
import com.certping.agent.listener.TestAttemptRecords;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.enums.CertType;
import com.certping.agent.model.message.CertIssuanceMessage;
import com.certping.agent.ssl.CaOrderAction;
import com.certping.agent.ssl.CaOrderCost;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.SslIssuanceService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertIssuanceProcessorTest {

    @Mock private SslIssuanceService sslIssuanceService;
    @Mock private AgentMessageSender sender;
    @Mock private ScheduledRetryService scheduledRetryService;
    @Mock private SecretStore secretStore;
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    @Mock private InboundContext context;

    private CertIssuanceProcessor processor;

    private static final IssuanceResult ISSUANCE_RESULT = new IssuanceResult(
            "https://kv.vault.azure.net/secrets/cert-xref-1",
            null,
            "https://kv.vault.azure.net/secrets/acme-acct",
            "ABCD1234",
            "AA:BB:CC:DD",
            OffsetDateTime.now(),
            OffsetDateTime.now().plusDays(90),
            "CN=Let's Encrypt",
            null,
            "SHA256withRSA",
            null, null, null,
            "RSA",
            2048,
            null, null, null, null, null,
            CertType.DV
    );

    @BeforeEach
    void setUp() {
        AttemptRecords attemptRecords = TestAttemptRecords.over(secretStore);
        processor = new CertIssuanceProcessor(sslIssuanceService, scheduledRetryService,
                new StoredResultPublisher(sender, secretStore, JsonMapper.builderWithJackson2Defaults().build(), meters, attemptRecords),
                attemptRecords, Clock.systemUTC());
    }

    private static IssuanceResult paidCaResult(CaOrderCost cost) {
        return new IssuanceResult("https://kv.vault.azure.net/secrets/cert-xref-1", null, null,
                "ABCD1234", "AA:BB:CC:DD", OffsetDateTime.now(), OffsetDateTime.now().plusDays(199),
                "CN=Example CA", "12345", "SHA256withRSA", null, null, null, "RSA", 2048,
                null, null, null, null, null, CertType.DV, cost, CaOrderAction.NEW_ORDER);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void process_success_sendsResponseAndCompletesMessage() {
        when(sslIssuanceService.issue(any())).thenReturn(ISSUANCE_RESULT);

        processor.process(buildMessage(), context);

        verify(sender).sendIssuanceResponse(any());
        verify(context).complete();
    }

    @Test
    void process_markTheLastPropagationWaitWhenItsRetriesAreUsedUp() {
        when(scheduledRetryService.retriesUsedUp(any(), eq("DNS_PROPAGATION_PENDING"))).thenReturn(true);
        when(sslIssuanceService.issue(any())).thenReturn(ISSUANCE_RESULT);

        processor.process(buildMessage(), context);

        verify(sslIssuanceService).issue(argThat(CertIssuanceMessage::isFinalPropagationWait));
    }

    @Test
    void process_success_responseContainsIssuanceFields() {
        when(sslIssuanceService.issue(any())).thenReturn(ISSUANCE_RESULT);

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> responseCaptor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(responseCaptor.capture());

        var resp = responseCaptor.getValue();
        assertThat(resp.getStatus()).isEqualTo("ISSUED");
        assertThat(resp.getCertSecretHandle()).isEqualTo(ISSUANCE_RESULT.certSecretHandle());
        assertThat(resp.getOrganizationId()).isEqualTo("organization-1");
        assertThat(resp.getCertificateXref()).isEqualTo("xref-1");
    }

    @Test
    void process_success_responseNamesWhoHoldsTheKey() {
        when(sslIssuanceService.issue(any())).thenReturn(ISSUANCE_RESULT.withKeyCustody(com.certping.agent.ssl.KeyCustody.CUSTOMER_HELD));

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> responseCaptor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(responseCaptor.capture());
        assertThat(responseCaptor.getValue().getKeyCustody()).isEqualTo("CUSTOMER_HELD");
    }

    @Test
    void process_success_responseContainsFingerprintAndDates() {
        when(sslIssuanceService.issue(any())).thenReturn(ISSUANCE_RESULT);

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());

        var resp = captor.getValue();
        assertThat(resp.getFingerprintSha256()).isEqualTo(ISSUANCE_RESULT.fingerprint());
        assertThat(resp.getSerialNumber()).isEqualTo(ISSUANCE_RESULT.serial());
        assertThat(resp.getIssuer()).isEqualTo(ISSUANCE_RESULT.issuer());
        assertThat(resp.getOrderId()).isEqualTo(ISSUANCE_RESULT.orderId());
        assertThat(resp.getRespondedAt()).isNotNull();
    }

    @Test
    void process_success_certSecretHandleWithVersionPropagatedToResponse() {
        IssuanceResult resultWithVersion = new IssuanceResult(
                "https://kv.vault.azure.net/secrets/cert-xref-1",
                "https://kv.vault.azure.net/secrets/cert-xref-1/versions/abc123",
                "https://kv.vault.azure.net/secrets/acme-acct",
                "ABCD1234", "AA:BB:CC:DD",
                OffsetDateTime.now(), OffsetDateTime.now().plusDays(90),
                "CN=DigiCert", null, "SHA256withRSA", null, null, null, "RSA",
                2048, null, null, null, null, null, CertType.DV
        );
        when(sslIssuanceService.issue(any())).thenReturn(resultWithVersion);

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());
        assertThat(captor.getValue().getCertSecretHandleWithVersion())
                .isEqualTo("https://kv.vault.azure.net/secrets/cert-xref-1/versions/abc123");
    }

    @Test
    void process_paidCaResultWithCost_responseCarriesCostAndCurrency() {
        when(sslIssuanceService.issue(any())).thenReturn(paidCaResult(new CaOrderCost("210.00", "USD")));

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());
        assertThat(captor.getValue().getCaOrderCost()).isEqualTo("210.00");
        assertThat(captor.getValue().getCaOrderCurrency()).isEqualTo("USD");
        assertThat(captor.getValue().getCaOrderAction()).isEqualTo("NEW_ORDER");
    }

    @Test
    void process_resultWithoutCost_responseHasNoCost() {
        when(sslIssuanceService.issue(any())).thenReturn(ISSUANCE_RESULT);

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());
        assertThat(captor.getValue().getCaOrderCost()).isNull();
        assertThat(captor.getValue().getCaOrderCurrency()).isNull();
        assertThat(captor.getValue().getCaOrderAction()).isNull();
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    @Test
    void process_sslServiceThrowsRuntimeException_rethrows() {
        RuntimeException boom = new TransientAgentException("ACME_NETWORK_ERROR", "network down");
        when(sslIssuanceService.issue(any())).thenThrow(boom);

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isSameAs(boom);

        verify(sender, never()).sendIssuanceResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_anOrderPendingAtTheCaIsPassedOnUnchanged() {
        IssuanceCheckpoint placed = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_FINALIZED,
                "9001", null, "https://kv.vault.azure.net/secrets/xref-1-key-staging");
        CaOrderPendingException pending = new CaOrderPendingException("DIGICERT", "9001", java.time.Duration.ofSeconds(15), placed);
        when(sslIssuanceService.issue(any())).thenThrow(pending);

        assertThatThrownBy(() -> processor.process(buildMessage(), context)).isSameAs(pending);

        verify(sender, never()).sendIssuanceResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_recordsNotVisibleBeforeTheLastWait_isRetried() {
        when(sslIssuanceService.issue(any()))
                .thenThrow(new PermanentAgentException("DNS_PROPAGATION_TIMEOUT", "CNAME not visible"));

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isInstanceOfSatisfying(RetryableAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_PROPAGATION_PENDING"));
    }

    @Test
    void process_recordsNotVisibleOnTheLastWait_fails() {
        when(scheduledRetryService.retriesUsedUp(any(), eq("DNS_PROPAGATION_PENDING"))).thenReturn(true);
        when(sslIssuanceService.issue(any()))
                .thenThrow(new PermanentAgentException("DNS_PROPAGATION_TIMEOUT", "CNAME not visible"));

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_PROPAGATION_TIMEOUT"));
    }

    @Test
    void process_sslServiceThrowsPermanentException_rethrows() {
        PermanentAgentException pae = new PermanentAgentException("ACME_ISSUANCE_FAILED", "bad request");
        when(sslIssuanceService.issue(any())).thenThrow(pae);

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isInstanceOf(PermanentAgentException.class);

        verify(sender, never()).sendIssuanceResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_senderPublishFails_keepsTheResultForTheNextAttempt() {
        when(sslIssuanceService.issue(any())).thenReturn(ISSUANCE_RESULT);
        doThrow(new TransientAgentException("SEND_FAILED", "bus unavailable"))
                .when(sender).sendIssuanceResponse(any());

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo("RESPONSE_PUBLISH_FAILED");
                    assertThat(e.getCheckpoint().step()).isEqualTo(IssuanceCheckpoint.Step.KV_STORED);
                    assertThat(e.getCheckpoint().response())
                            .contains("\"certificateXref\":\"xref-1\"")
                            .contains("\"status\":\"ISSUED\"")
                            .contains(ISSUANCE_RESULT.certSecretHandle());
                });
        verify(context, never()).complete();
        verify(context, never()).deadLetter(any());
    }

    @Test
    void process_aMessagePastItsDeadlineOrdersNothing() {
        doThrow(new PermanentAgentException("ATTEMPT_DEADLINE_PASSED", "late"))
                .when(scheduledRetryService).requireTimeLeft(any());

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("ATTEMPT_DEADLINE_PASSED"));
        verify(sslIssuanceService, never()).issue(any());
    }

    @Test
    void process_aStoredResultIsSentAgainWithoutIssuing() {
        StoredResults.deliverStored(context, StoredResults.storedResult("xref-1"));
        StoredResults.storeMatchingCertificate(secretStore);

        processor.process(buildMessage(), context);

        verify(sslIssuanceService, never()).issue(any());
        verify(sender).sendIssuanceResponse(argThat(r -> "xref-1".equals(r.getCertificateXref())));
        verify(context).complete();
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private CertIssuanceMessage buildMessage() {
        CertIssuanceMessage msg = new CertIssuanceMessage();
        msg.setRequestId("req-1");
        msg.setCorrelationId("corr-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCaProvider(CaProvider.LETS_ENCRYPT);
        msg.setDnsProvider("CLOUDFLARE");
        msg.setWildcard(false);
        msg.setSan(false);
        return msg;
    }
}
