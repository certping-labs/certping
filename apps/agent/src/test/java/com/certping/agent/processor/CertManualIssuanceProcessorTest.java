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
import com.certping.agent.model.message.CertManualTxtRequestMessage;
import com.certping.agent.model.message.CertManualTxtResponse;
import com.certping.agent.model.message.CertManualValidateMessage;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.acme.LetsEncryptManualService;
import com.certping.agent.ssl.acme.ManualTxtResult;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URL;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertManualIssuanceProcessorTest {

    @Mock private LetsEncryptManualService letsEncryptManualService;
    @Mock private AgentMessageSender sender;
    @Mock private SecretStore secretStore;
    @Mock private ScheduledRetryService scheduledRetryService;
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    @Mock private InboundContext context;

    private CertManualIssuanceProcessor processor;

    private static final IssuanceResult ISSUANCE_RESULT = new IssuanceResult(
            "https://kv.vault.azure.net/secrets/cert-xref-1",
            null,
            "https://kv.vault.azure.net/secrets/acme-acct",
            "ABCD1234",
            "AA:BB:CC:DD",
            OffsetDateTime.parse("2025-01-01T00:00:00Z"),
            OffsetDateTime.parse("2025-04-01T00:00:00Z"),
            "CN=R3,O=Let's Encrypt,C=US",
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
        processor = new CertManualIssuanceProcessor(letsEncryptManualService, sender,
                new StoredResultPublisher(sender, secretStore, JsonMapper.builderWithJackson2Defaults().build(), meters, attemptRecords),
                attemptRecords, scheduledRetryService, Clock.systemUTC());
    }

    // ── CERT_MANUAL_TXT_REQUEST ───────────────────────────────────────────────

    @Test
    void processManualTxtRequest_success_sendsResponseAndCompletes() throws Exception {
        CertManualTxtRequestMessage msg = validTxtRequest();
        ManualTxtResult result = new ManualTxtResult(
                List.of(CertManualTxtResponse.TxtRecord.builder()
                        .domain("example.com")
                        .recordName("_acme-challenge.example.com")
                        .recordValue("digest-abc")
                        .build()),
                new URL("https://acme.test/order/1"),
                new URL("https://acme.test/acct/1"),
                "https://kv.vault.azure.net/secrets/acme-1");

        when(letsEncryptManualService.requestTxtRecords(
                eq("organization-1"), eq("xref-1"), eq("example.com"),
                eq(false), eq(false), eq(null), eq(null)))
                .thenReturn(result);

        processor.processManualTxtRequest(msg, context);

        ArgumentCaptor<CertManualTxtResponse> captor = ArgumentCaptor.forClass(CertManualTxtResponse.class);
        verify(sender).sendManualTxtResponse(captor.capture());
        verify(context).complete();

        CertManualTxtResponse out = captor.getValue();
        assertThat(out.getRequestId()).isEqualTo("req-txt");
        assertThat(out.getCorrelationId()).isEqualTo("corr-txt");
        assertThat(out.getOrganizationId()).isEqualTo("organization-1");
        assertThat(out.getCertificateXref()).isEqualTo("xref-1");
        assertThat(out.getAcmeOrderUrl()).isEqualTo("https://acme.test/order/1");
        assertThat(out.getAcmeAccountHandle()).isEqualTo("https://kv.vault.azure.net/secrets/acme-1");
        assertThat(out.getTxtRecords()).hasSize(1);
        assertThat(out.getTxtRecords().get(0).getRecordValue()).isEqualTo("digest-abc");
        assertThat(out.getRespondedAt()).isNotNull();
    }

    @Test
    void processManualTxtRequest_missingOrganizationId_throws() {
        CertManualTxtRequestMessage msg = validTxtRequest();
        msg.setOrganizationId(" ");

        assertThatThrownBy(() -> processor.processManualTxtRequest(msg, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MANUAL_TXT_REQUEST_INVALID"));

        verify(sender, never()).sendManualTxtResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void processManualTxtRequest_missingCertificateXref_throws() {
        CertManualTxtRequestMessage msg = validTxtRequest();
        msg.setCertificateXref(null);

        assertThatThrownBy(() -> processor.processManualTxtRequest(msg, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MANUAL_TXT_REQUEST_INVALID"));

        verify(sender, never()).sendManualTxtResponse(any());
    }

    @Test
    void processManualTxtRequest_missingDomain_throws() {
        CertManualTxtRequestMessage msg = validTxtRequest();
        msg.setDomain("");

        assertThatThrownBy(() -> processor.processManualTxtRequest(msg, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MANUAL_TXT_REQUEST_INVALID"));
    }

    @Test
    void processManualTxtRequest_unsupportedCa_throws() {
        CertManualTxtRequestMessage msg = validTxtRequest();
        msg.setCaProvider(CaProvider.DIGICERT);

        assertThatThrownBy(() -> processor.processManualTxtRequest(msg, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("UNSUPPORTED_CA_FOR_MANUAL"));

        verify(letsEncryptManualService, never()).requestTxtRecords(
                anyString(), anyString(), anyString(), anyBoolean(), anyBoolean(), any(), any());
    }

    @Test
    void processManualTxtRequest_nullCa_throws() {
        CertManualTxtRequestMessage msg = validTxtRequest();
        msg.setCaProvider(null);

        assertThatThrownBy(() -> processor.processManualTxtRequest(msg, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("UNSUPPORTED_CA_FOR_MANUAL"));
    }

    @Test
    void processManualTxtRequest_serviceThrowsTransient_propagates() throws Exception {
        CertManualTxtRequestMessage msg = validTxtRequest();
        when(letsEncryptManualService.requestTxtRecords(anyString(), anyString(), anyString(),
                anyBoolean(), anyBoolean(), any(), any()))
                .thenThrow(new TransientAgentException("ACME_NETWORK_ERROR", "down"));

        assertThatThrownBy(() -> processor.processManualTxtRequest(msg, context))
                .isInstanceOf(TransientAgentException.class);

        verify(sender, never()).sendManualTxtResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void processManualTxtRequest_senderPublishFails_deadLettersWithReason() throws Exception {
        CertManualTxtRequestMessage msg = validTxtRequest();
        ManualTxtResult result = new ManualTxtResult(
                List.of(CertManualTxtResponse.TxtRecord.builder()
                        .domain("example.com")
                        .recordName("_acme-challenge.example.com")
                        .recordValue("digest-abc")
                        .build()),
                new URL("https://acme.test/order/xyz"),
                new URL("https://acme.test/acct/1"),
                "https://kv.vault.azure.net/secrets/acme-1");

        when(letsEncryptManualService.requestTxtRecords(
                anyString(), anyString(), anyString(), anyBoolean(), anyBoolean(), any(), any()))
                .thenReturn(result);
        doThrow(new RuntimeException("gateway send failed"))
                .when(sender).sendManualTxtResponse(any());

        processor.processManualTxtRequest(msg, context);

        // context.complete() must NOT be called — instead deadLetter runs with the CRITICAL reason.
        verify(context, never()).complete();
        ArgumentCaptor<com.certping.agent.transport.DeadLetterOptions> dlq =
                ArgumentCaptor.forClass(com.certping.agent.transport.DeadLetterOptions.class);
        verify(context).deadLetter(dlq.capture());
        assertThat(dlq.getValue().getDeadLetterReason()).isEqualTo("MANUAL_TXT_RESPONSE_PUBLISH_FAILED");
        assertThat(dlq.getValue().getDeadLetterErrorDescription())
                .contains("https://acme.test/order/xyz")
                .contains("gateway send failed");
    }

    // ── CERT_MANUAL_DNS_VALIDATE ──────────────────────────────────────────────

    @Test
    void processManualDnsValidation_success_sendsIssuanceResponseAndCompletes() {
        CertManualValidateMessage msg = validValidateMessage();
        when(letsEncryptManualService.completeValidation(
                anyString(), anyString(), anyString(), anyBoolean(), anyBoolean(),
                any(), anyString(), anyString(), any()))
                .thenReturn(ISSUANCE_RESULT);

        processor.processManualDnsValidation(msg, context);

        verify(sender).sendIssuanceResponse(argThat(r ->
                "ISSUED".equals(r.getStatus())
                        && r.getCaProvider() == CaProvider.LETS_ENCRYPT
                        && ISSUANCE_RESULT.certSecretHandle().equals(r.getCertSecretHandle())
                        && ISSUANCE_RESULT.acmeAccountHandle().equals(r.getAcmeAccountHandle())
                        && ISSUANCE_RESULT.serial().equals(r.getSerialNumber())
                        && ISSUANCE_RESULT.fingerprint().equals(r.getFingerprintSha256())
                        && ISSUANCE_RESULT.issuer().equals(r.getIssuer())
                        && java.util.Objects.equals(ISSUANCE_RESULT.orderId(), r.getOrderId())
                        && "organization-1".equals(r.getOrganizationId())
                        && "xref-1".equals(r.getCertificateXref())));
        verify(context).complete();
    }

    @Test
    void processManualDnsValidation_recordsNotVisibleYet_isRetried() {
        CertManualValidateMessage msg = validValidateMessage();
        when(letsEncryptManualService.completeValidation(
                anyString(), anyString(), anyString(), anyBoolean(), anyBoolean(),
                any(), anyString(), anyString(), any()))
                .thenThrow(new PermanentAgentException("DNS_PROPAGATION_TIMEOUT", "not visible"));

        assertThatThrownBy(() -> processor.processManualDnsValidation(msg, context))
                .isInstanceOfSatisfying(RetryableAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_PROPAGATION_PENDING"));
    }

    @Test
    void processManualDnsValidation_recordsNotVisibleOnTheLastWait_fails() {
        CertManualValidateMessage msg = validValidateMessage();
        when(scheduledRetryService.retriesUsedUp(any(), eq("DNS_PROPAGATION_PENDING"))).thenReturn(true);
        when(letsEncryptManualService.completeValidation(
                anyString(), anyString(), anyString(), anyBoolean(), anyBoolean(),
                any(), anyString(), anyString(), any()))
                .thenThrow(new PermanentAgentException("DNS_PROPAGATION_TIMEOUT", "not visible"));

        assertThatThrownBy(() -> processor.processManualDnsValidation(msg, context))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("DNS_PROPAGATION_TIMEOUT"));
    }

    @Test
    void processManualDnsValidation_nullCa_throws() {
        CertManualValidateMessage msg = validValidateMessage();
        msg.setCaProvider(null);

        assertThatThrownBy(() -> processor.processManualDnsValidation(msg, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("UNSUPPORTED_CA_FOR_MANUAL"));

        verify(letsEncryptManualService, never()).completeValidation(
                anyString(), anyString(), anyString(), anyBoolean(), anyBoolean(),
                any(), anyString(), anyString(), any());
    }

    @Test
    void processManualDnsValidation_senderPublishFails_keepsTheResultForTheNextAttempt() {
        CertManualValidateMessage msg = validValidateMessage();
        when(letsEncryptManualService.completeValidation(
                anyString(), anyString(), anyString(), anyBoolean(), anyBoolean(),
                any(), anyString(), anyString(), any()))
                .thenReturn(ISSUANCE_RESULT);
        doThrow(new TransientAgentException("SEND_FAILED", "bus down"))
                .when(sender).sendIssuanceResponse(any());

        assertThatThrownBy(() -> processor.processManualDnsValidation(msg, context))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo("RESPONSE_PUBLISH_FAILED");
                    assertThat(e.getCheckpoint().step()).isEqualTo(IssuanceCheckpoint.Step.KV_STORED);
                });
        verify(context, never()).complete();
        verify(context, never()).deadLetter(any());
    }

    @Test
    void processManualDnsValidation_aStoredResultIsSentAgainWithoutValidating() {
        CertManualValidateMessage msg = validValidateMessage();
        StoredResults.deliverStored(context, StoredResults.storedResult(msg.getCertificateXref()));
        StoredResults.storeMatchingCertificate(secretStore);

        processor.processManualDnsValidation(msg, context);

        verify(letsEncryptManualService, never()).completeValidation(
                any(), any(), any(), anyBoolean(), anyBoolean(), any(), any(), any(), any());
        verify(sender).sendIssuanceResponse(any());
        verify(context).complete();
    }

    @Test
    void processManualDnsValidation_unsupportedCa_throws() {
        CertManualValidateMessage msg = validValidateMessage();
        msg.setCaProvider(CaProvider.DIGICERT);

        assertThatThrownBy(() -> processor.processManualDnsValidation(msg, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("UNSUPPORTED_CA_FOR_MANUAL"));

        verify(letsEncryptManualService, never()).completeValidation(
                anyString(), anyString(), anyString(), anyBoolean(), anyBoolean(),
                any(), anyString(), anyString(), any());
        verify(sender, never()).sendIssuanceResponse(any());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static CertManualTxtRequestMessage validTxtRequest() {
        CertManualTxtRequestMessage msg = new CertManualTxtRequestMessage();
        msg.setRequestId("req-txt");
        msg.setCorrelationId("corr-txt");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setWildcard(false);
        msg.setSan(false);
        msg.setCaProvider(CaProvider.LETS_ENCRYPT);
        return msg;
    }

    private static CertManualValidateMessage validValidateMessage() {
        CertManualValidateMessage msg = new CertManualValidateMessage();
        msg.setRequestId("req-val");
        msg.setCorrelationId("corr-val");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setWildcard(false);
        msg.setSan(false);
        msg.setCaProvider(CaProvider.LETS_ENCRYPT);
        msg.setAcmeOrderUrl("https://acme.test/order/1");
        msg.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme-1");
        return msg;
    }
}
