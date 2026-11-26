// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertRevocationMessage;
import com.certping.agent.model.message.CertRevocationResponse;
import com.certping.agent.ssl.SslRevocationService;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertRevocationProcessorTest {

    @Mock private SecretStore secretStore;
    @Mock private SslRevocationService revocationService;
    @Mock private AgentMessageSender   sender;
    @Mock private InboundContext context;

    private CertRevocationProcessor processor;

    private static final String CERT_BUNDLE = """
            -----BEGIN CERTIFICATE-----
            MIIBxyz
            -----END CERTIFICATE-----
            -----BEGIN PRIVATE KEY-----
            MIIEvg==
            -----END PRIVATE KEY-----""";

    @BeforeEach
    void setUp() {
        processor = new CertRevocationProcessor(secretStore, revocationService, sender);
    }

    // ── Happy path: Let's Encrypt ─────────────────────────────────────────────

    @Test
    void process_letsEncrypt_revokesAndCompletesMessage() {
        when(secretStore.read("https://kv.vault.azure.net/secrets/cert-xref-1"))
                .thenReturn(CERT_BUNDLE);
        when(secretStore.isOwnedByThisAgent("https://kv.vault.azure.net/secrets/cert-xref-1"))
                .thenReturn(true);

        processor.process(buildLeMessage(), context);

        verify(revocationService).revoke(
                eq(CaProvider.LETS_ENCRYPT), eq(CERT_BUNDLE), eq(null), eq("KEY_COMPROMISE"), eq(null));
        verify(secretStore).isOwnedByThisAgent("https://kv.vault.azure.net/secrets/cert-xref-1");
        verify(secretStore).delete("https://kv.vault.azure.net/secrets/cert-xref-1");
        verify(sender).sendRevocationResponse(any());
        verify(context).complete();
    }

    // ── Happy path: DigiCert ──────────────────────────────────────────────────

    @Test
    void process_digiCert_readsApiKeyAndRevokes() {
        when(secretStore.read("https://kv.vault.azure.net/secrets/dc-api-key"))
                .thenReturn("dc-api-key-12345");
        when(secretStore.isOwnedByThisAgent("https://kv.vault.azure.net/secrets/cert-xref-dc"))
                .thenReturn(true);

        processor.process(buildDcMessage(), context);

        verify(revocationService).revoke(
                eq(CaProvider.DIGICERT), eq(null), eq("order-9001"), eq("SUPERSEDED"), eq("dc-api-key-12345"));
        verify(secretStore).isOwnedByThisAgent("https://kv.vault.azure.net/secrets/cert-xref-dc");
        verify(secretStore).delete("https://kv.vault.azure.net/secrets/cert-xref-dc");
        verify(sender).sendRevocationResponse(any());
        verify(context).complete();
    }

    // ── Response payload ──────────────────────────────────────────────────────

    @Test
    void process_letsEncrypt_responseContainsCorrectFields() {
        when(secretStore.read(anyString())).thenReturn(CERT_BUNDLE);

        processor.process(buildLeMessage(), context);

        ArgumentCaptor<CertRevocationResponse> captor = ArgumentCaptor.forClass(CertRevocationResponse.class);
        verify(sender).sendRevocationResponse(captor.capture());

        CertRevocationResponse resp = captor.getValue();
        assertThat(resp.getRequestId()).isEqualTo("req-rev-1");
        assertThat(resp.getCorrelationId()).isEqualTo("corr-rev-1");
        assertThat(resp.getOrganizationId()).isEqualTo("organization-1");
        assertThat(resp.getCertificateXref()).isEqualTo("xref-1");
        assertThat(resp.getCaProvider()).isEqualTo(CaProvider.LETS_ENCRYPT);
        assertThat(resp.getRevocationReason()).isEqualTo("KEY_COMPROMISE");
        assertThat(resp.getRevokedAt()).isNotNull();
    }

        @Test
        void process_letsEncrypt_userIdNullable_stillRevokesAndCompletes() {
                when(secretStore.read("https://kv.vault.azure.net/secrets/cert-xref-1"))
                                .thenReturn(CERT_BUNDLE);
                when(secretStore.isOwnedByThisAgent("https://kv.vault.azure.net/secrets/cert-xref-1"))
                                .thenReturn(true);

                CertRevocationMessage msg = buildLeMessage();
                msg.setUserId(null);

                processor.process(msg, context);

                verify(revocationService).revoke(
                                eq(CaProvider.LETS_ENCRYPT), eq(CERT_BUNDLE), eq(null), eq("KEY_COMPROMISE"), eq(null));
                verify(secretStore).isOwnedByThisAgent("https://kv.vault.azure.net/secrets/cert-xref-1");
                verify(secretStore).delete("https://kv.vault.azure.net/secrets/cert-xref-1");
                verify(sender).sendRevocationResponse(any());
                verify(context).complete();
        }

    // ── Bundle not found in KV ────────────────────────────────────────────────

    @Test
    void process_bundleNullFromKv_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn(null);

        assertThatThrownBy(() -> processor.process(buildLeMessage(), context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KV_SECRET_NOT_FOUND"));

        verify(revocationService, never()).revoke(any(), any(), any(), any(), any());
        verify(context, never()).complete();
    }

    @Test
    void process_bundleBlankFromKv_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn("   ");

        assertThatThrownBy(() -> processor.process(buildLeMessage(), context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KV_SECRET_NOT_FOUND"));

        verify(revocationService, never()).revoke(any(), any(), any(), any(), any());
    }

    // ── DigiCert: missing caCredentialHandle ────────────────────────────────────

    @Test
    void process_digiCert_missingCaCredentialHandle_throwsPermanent() {
        CertRevocationMessage msg = buildDcMessage();
        msg.setCaCredentialHandle(null);

        assertThatThrownBy(() -> processor.process(msg, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MISSING_CA_CREDENTIAL"));

        verify(revocationService, never()).revoke(any(), any(), any(), any(), any());
    }

    // ── DigiCert: API key blank in KV ─────────────────────────────────────────

    @Test
    void process_digiCert_apiKeyBlankInKv_throwsPermanent() {
        when(secretStore.read("https://kv.vault.azure.net/secrets/dc-api-key"))
                .thenReturn("");

        assertThatThrownBy(() -> processor.process(buildDcMessage(), context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KV_SECRET_NOT_FOUND"));

        verify(revocationService, never()).revoke(any(), any(), any(), any(), any());
    }

    // ── revocationService failures ────────────────────────────────────────────

    @Test
    void process_revocationServiceThrowsPermanent_rethrows() {
        when(secretStore.read(anyString())).thenReturn(CERT_BUNDLE);
        PermanentAgentException ex = new PermanentAgentException("REVOCATION_FAILED", "CA rejected");
        doThrow(ex).when(revocationService).revoke(any(), any(), any(), any(), any());

        assertThatThrownBy(() -> processor.process(buildLeMessage(), context))
                .isSameAs(ex);

        verify(sender, never()).sendRevocationResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_revocationServiceThrowsTransient_rethrows() {
        when(secretStore.read(anyString())).thenReturn(CERT_BUNDLE);
        TransientAgentException ex = new TransientAgentException("REVOCATION_TRANSIENT", "network down");
        doThrow(ex).when(revocationService).revoke(any(), any(), any(), any(), any());

        assertThatThrownBy(() -> processor.process(buildLeMessage(), context))
                .isSameAs(ex);

        verify(sender, never()).sendRevocationResponse(any());
        verify(context, never()).complete();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CertRevocationMessage buildLeMessage() {
        CertRevocationMessage msg = new CertRevocationMessage();
        msg.setRequestId("req-rev-1");
        msg.setCorrelationId("corr-rev-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCaProvider(CaProvider.LETS_ENCRYPT);
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setRevocationReason("KEY_COMPROMISE");
        msg.setUserId(123);
        return msg;
    }

    private CertRevocationMessage buildDcMessage() {
        CertRevocationMessage msg = new CertRevocationMessage();
        msg.setRequestId("req-rev-2");
        msg.setCorrelationId("corr-rev-2");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-dc");
        msg.setDomain("dc-example.com");
        msg.setCaProvider(CaProvider.DIGICERT);
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-dc");
        msg.setOrderId("order-9001");
        msg.setRevocationReason("SUPERSEDED");
        msg.setCaCredentialHandle("https://kv.vault.azure.net/secrets/dc-api-key");
        return msg;
    }
}
