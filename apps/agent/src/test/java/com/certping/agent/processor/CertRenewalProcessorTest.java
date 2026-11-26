// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
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
import com.certping.agent.model.message.CertRenewalMessage;
import com.certping.agent.ssl.CaOrderAction;
import com.certping.agent.ssl.CaOrderCost;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.SslRenewalService;
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
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertRenewalProcessorTest {

    @Mock private SslRenewalService sslRenewalService;
    @Mock private AgentMessageSender sender;
    @Mock private ScheduledRetryService scheduledRetryService;
    @Mock private SecretStore secretStore;
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    @Mock private InboundContext context;

    private CertRenewalProcessor processor;

    private static final IssuanceResult RESULT = new IssuanceResult(
            "https://kv.vault.azure.net/secrets/cert-xref-1",
            null,
            "https://kv.vault.azure.net/secrets/acme-acct",
            "ABCD1234", "AA:BB:CC:DD",
            OffsetDateTime.now(), OffsetDateTime.now().plusDays(90), "CN=Let's Encrypt",
            "987654321",
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
        processor = new CertRenewalProcessor(sslRenewalService, scheduledRetryService,
                new StoredResultPublisher(sender, secretStore, JsonMapper.builderWithJackson2Defaults().build(), meters, attemptRecords),
                attemptRecords, Clock.systemUTC());
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void process_success_sendsResponseAndCompletesMessage() {
        when(sslRenewalService.renew(any())).thenReturn(RESULT);

        processor.process(buildMessage(), context);

        verify(sender).sendIssuanceResponse(any());
        verify(context).complete();
    }

    @Test
    void process_success_responseHasRenewedStatus() {
        when(sslRenewalService.renew(any())).thenReturn(RESULT);

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());

        var resp = captor.getValue();
        assertThat(resp.getStatus()).isEqualTo("RENEWED");
        assertThat(resp.getOrganizationId()).isEqualTo("organization-1");
        assertThat(resp.getCertificateXref()).isEqualTo("xref-1");
        assertThat(resp.getCertSecretHandle()).isEqualTo(RESULT.certSecretHandle());
    }

    @Test
    void process_success_responseContainsCertDetails() {
        when(sslRenewalService.renew(any())).thenReturn(RESULT);

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());

        var resp = captor.getValue();
        assertThat(resp.getSerialNumber()).isEqualTo(RESULT.serial());
        assertThat(resp.getFingerprintSha256()).isEqualTo(RESULT.fingerprint());
        assertThat(resp.getOrderId()).isEqualTo(RESULT.orderId());
        assertThat(resp.getRespondedAt()).isNotNull();
    }

    @Test
    void process_paidCaRenewalWithCost_responseCarriesCost() {
        when(sslRenewalService.renew(any())).thenReturn(new IssuanceResult(
                "https://kv.vault.azure.net/secrets/cert-xref-1", null, null,
                "ABCD1234", "AA:BB:CC:DD", OffsetDateTime.now(), OffsetDateTime.now().plusDays(199),
                "CN=Example CA", "12346", "SHA256withRSA", null, null, null, "RSA", 2048,
                null, null, null, null, null, CertType.DV, new CaOrderCost("210.00", null),
                CaOrderAction.NEW_ORDER));

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());
        assertThat(captor.getValue().getCaOrderCost()).isEqualTo("210.00");
        assertThat(captor.getValue().getCaOrderCurrency()).isNull();
        assertThat(captor.getValue().getCaOrderAction()).isEqualTo("NEW_ORDER");
    }

    @Test
    void process_replacement_responseSaysReplacementWithNoCost() {
        when(sslRenewalService.renew(any())).thenReturn(new IssuanceResult(
                "https://kv.vault.azure.net/secrets/cert-xref-1", null, null,
                "ABCD1235", "AA:BB:CC:DE", OffsetDateTime.now(), OffsetDateTime.now().plusDays(160),
                "CN=Example CA", "12346", "SHA256withRSA", null, null, null, "RSA", 2048,
                null, null, null, null, null, CertType.DV, null, CaOrderAction.REPLACEMENT));

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());
        assertThat(captor.getValue().getCaOrderAction()).isEqualTo("REPLACEMENT");
        assertThat(captor.getValue().getCaOrderCost()).isNull();
        assertThat(captor.getValue().getOrderId()).isEqualTo("12346");
    }

    @Test
    void process_renewalWithoutCost_responseHasNoCost() {
        when(sslRenewalService.renew(any())).thenReturn(RESULT);

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertIssuanceResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertIssuanceResponse.class);
        verify(sender).sendIssuanceResponse(captor.capture());
        assertThat(captor.getValue().getCaOrderCost()).isNull();
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    @Test
    void process_renewalFails_rethrowsTransientException() {
        TransientAgentException ex = new TransientAgentException("ACME_NETWORK_ERROR", "network down");
        when(sslRenewalService.renew(any())).thenThrow(ex);

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isSameAs(ex);

        verify(sender, never()).sendIssuanceResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_renewalFails_rethrowsPermanentException() {
        PermanentAgentException ex = new PermanentAgentException("CA_ORDER_TIMEOUT", "timeout");
        when(sslRenewalService.renew(any())).thenThrow(ex);

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isInstanceOf(PermanentAgentException.class);

        verify(sender, never()).sendIssuanceResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_senderPublishFails_keepsTheResultInsteadOfRenewingAgain() {
        when(sslRenewalService.renew(any())).thenReturn(RESULT);
        doThrow(new TransientAgentException("SEND_FAILED", "bus unavailable"))
                .when(sender).sendIssuanceResponse(any());

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo("RESPONSE_PUBLISH_FAILED");
                    assertThat(e.getCheckpoint().step()).isEqualTo(IssuanceCheckpoint.Step.KV_STORED);
                    assertThat(e.getCheckpoint().response()).contains("\"status\":\"RENEWED\"");
                });
        verify(context, never()).complete();
    }

    @Test
    void process_aStoredResultIsSentAgainWithoutRenewing() {
        CertRenewalMessage message = buildMessage();
        StoredResults.deliverStored(context, StoredResults.storedResult(message.getCertificateXref()));
        StoredResults.storeMatchingCertificate(secretStore);

        processor.process(message, context);

        verify(sslRenewalService, never()).renew(any());
        verify(sender).sendIssuanceResponse(any());
        verify(context).complete();
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private CertRenewalMessage buildMessage() {
        CertRenewalMessage msg = new CertRenewalMessage();
        msg.setRequestId("req-2");
        msg.setCorrelationId("corr-2");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCaProvider(CaProvider.LETS_ENCRYPT);
        msg.setDnsProvider("CLOUDFLARE");
        msg.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/cf-token");
        return msg;
    }
}
