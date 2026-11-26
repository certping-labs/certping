// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.model.message.CertSecretDeleteMessage;
import com.certping.agent.model.message.CertSecretDeleteResponse;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertSecretDeleteProcessorTest {

    @Mock private SecretStore secretStore;
    @Mock private AttemptRecords attemptRecords;
    @Mock private AgentMessageSender               sender;
    @Mock private InboundContext context;

    private CertSecretDeleteProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new CertSecretDeleteProcessor(secretStore, attemptRecords, sender);
    }

    @Test
    void process_deletesSecretAndRespondsSuccess() {
        CertSecretDeleteMessage msg = buildMsg("https://kv.vault.azure.net/secrets/cert-xref-1");

        processor.process(msg, context);

        verify(secretStore).delete("https://kv.vault.azure.net/secrets/cert-xref-1");
        verify(attemptRecords).delete("xref-1");
        verify(context).complete();

        ArgumentCaptor<CertSecretDeleteResponse> captor = ArgumentCaptor.forClass(CertSecretDeleteResponse.class);
        verify(sender).sendKvDeleteResponse(captor.capture());

        CertSecretDeleteResponse resp = captor.getValue();
        assertThat(resp.getStatus()).isEqualTo("SUCCESS");
        assertThat(resp.getErrorCode()).isNull();
        assertThat(resp.getErrorDetail()).isNull();
        assertThat(resp.getCertificateXref()).isEqualTo("xref-1");
        assertThat(resp.getOrganizationId()).isEqualTo("org-1");
        assertThat(resp.getRequestId()).isEqualTo("req-1");
        assertThat(resp.getCorrelationId()).isEqualTo("corr-1");
        assertThat(resp.getRespondedAt()).isNotNull();
    }

    @Test
    void process_nullCertSecretHandle_respondsSkipped() {
        CertSecretDeleteMessage msg = buildMsg(null);

        processor.process(msg, context);

        verify(secretStore, never()).delete(any());
        verify(context).complete();

        ArgumentCaptor<CertSecretDeleteResponse> captor = ArgumentCaptor.forClass(CertSecretDeleteResponse.class);
        verify(sender).sendKvDeleteResponse(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("SKIPPED");
    }

    @Test
    void process_blankCertSecretHandle_respondsSkipped() {
        CertSecretDeleteMessage msg = buildMsg("   ");

        processor.process(msg, context);

        verify(secretStore, never()).delete(any());
        verify(context).complete();

        ArgumentCaptor<CertSecretDeleteResponse> captor = ArgumentCaptor.forClass(CertSecretDeleteResponse.class);
        verify(sender).sendKvDeleteResponse(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("SKIPPED");
    }

    @Test
    void process_kvDeleteThrows_respondsFailed() {
        CertSecretDeleteMessage msg = buildMsg("https://kv.vault.azure.net/secrets/cert-xref-1");
        doThrow(new RuntimeException("vault unavailable"))
                .when(secretStore).delete(any());

        processor.process(msg, context);

        verify(context).complete();

        ArgumentCaptor<CertSecretDeleteResponse> captor = ArgumentCaptor.forClass(CertSecretDeleteResponse.class);
        verify(sender).sendKvDeleteResponse(captor.capture());

        CertSecretDeleteResponse resp = captor.getValue();
        assertThat(resp.getStatus()).isEqualTo("FAILED");
        assertThat(resp.getErrorCode()).isEqualTo("KV_DELETE_FAILED");
        assertThat(resp.getErrorDetail()).contains("vault unavailable");
    }

    @Test
    void process_responseAlwaysIncludesMetadata() {
        CertSecretDeleteMessage msg = buildMsg("https://kv.vault.azure.net/secrets/cert-xref-1");

        processor.process(msg, context);

        ArgumentCaptor<CertSecretDeleteResponse> captor = ArgumentCaptor.forClass(CertSecretDeleteResponse.class);
        verify(sender).sendKvDeleteResponse(captor.capture());

        CertSecretDeleteResponse resp = captor.getValue();
        assertThat(resp.getRequestId()).isEqualTo("req-1");
        assertThat(resp.getCorrelationId()).isEqualTo("corr-1");
        assertThat(resp.getOrganizationId()).isEqualTo("org-1");
        assertThat(resp.getCertificateXref()).isEqualTo("xref-1");
        assertThat(resp.getRespondedAt()).isNotNull();
    }

    private CertSecretDeleteMessage buildMsg(String certSecretHandle) {
        return CertSecretDeleteMessage.builder()
                .requestId("req-1")
                .correlationId("corr-1")
                .organizationId("org-1")
                .certificateXref("xref-1")
                .certSecretHandle(certSecretHandle)
                .requestedAt("2026-05-01T00:00:00Z")
                .build();
    }
}
