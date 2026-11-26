// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.discovery.DiscoveryAdapter;
import com.certping.agent.discovery.DiscoveryAdapterFactory;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.CertDiscoveryResponse;
import com.certping.agent.model.message.DiscoveredCertEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertDiscoveryProcessorTest {

    @Mock private DiscoveryAdapterFactory adapterFactory;
    @Mock private DiscoveryAdapter discoveryAdapter;
    @Mock private AgentMessageSender sender;
    @Mock private InboundContext context;

    private CertDiscoveryProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new CertDiscoveryProcessor(adapterFactory, sender);
        // A Mockito mock does not run interface default methods; let the default delegate to discover().
        org.mockito.Mockito.lenient().when(discoveryAdapter.discoverWithFailedScopes(any())).thenCallRealMethod();
    }

    @Test
    void process_partialScan_sendsFailedScopesOnEveryBatchAndOnCompletion() {
        CertDiscoveryMessage message = buildMessage();
        List<DiscoveredCertEntry> discovered = IntStream.range(0, 60)
                .mapToObj(i -> DiscoveredCertEntry.builder().resourceId("r-" + i).domain("d").build())
                .toList();
        com.certping.agent.model.message.DiscoveryFailedScope failed =
                com.certping.agent.model.message.DiscoveryFailedScope.of(
                        com.certping.agent.model.message.DiscoveryFailedScope.ScopeType.AWS_ACCOUNT,
                        "222222222222", "DISCOVERY_AWS_ACCOUNT_ACCESS_DENIED", "AccessDenied");
        when(adapterFactory.create(TargetType.AWS_ACM)).thenReturn(discoveryAdapter);
        org.mockito.Mockito.doReturn(new com.certping.agent.discovery.DiscoveryResult(discovered, List.of(failed)))
                .when(discoveryAdapter).discoverWithFailedScopes(message);

        processor.process(message, context);

        ArgumentCaptor<CertDiscoveryResponse> responses = ArgumentCaptor.forClass(CertDiscoveryResponse.class);
        verify(sender, times(2)).sendDiscoveryResponse(responses.capture());
        assertThat(responses.getAllValues()).allSatisfy(r -> assertThat(r.getFailedScopes()).containsExactly(failed));
        ArgumentCaptor<com.certping.agent.model.message.CertDiscoveryCompleteMessage> complete =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertDiscoveryCompleteMessage.class);
        verify(sender).sendDiscoveryComplete(complete.capture());
        assertThat(complete.getValue().getFailedScopes()).containsExactly(failed);
        verify(context).complete();
    }

    @Test
    void process_successfulScan_sendsResponseAndCompletesMessage() {
        CertDiscoveryMessage message = buildMessage();
        List<DiscoveredCertEntry> discovered = List.of(
                DiscoveredCertEntry.builder()
                        .resourceId("arn:aws:acm:us-east-1:123:certificate/abc")
                        .domain("test.example.net")
                        .subjectDn("CN=test.example.net,O=CertPing Test")
                        .sanDomains(List.of("test.example.net"))
                        .keyAlgorithm("RSA-2048")
                        .signatureAlgorithm("SHA256WITHRSA")
                        .issuer("CertPing Test")
                        .certStatus("ISSUED")
                        .keyUsage("DIGITAL_SIGNATURE,KEY_ENCIPHERMENT")
                        .extendedKeyUsage("TLS_WEB_SERVER_AUTHENTICATION")
                        .certType("IMPORTED")
                        .inUseBy(List.of())
                        .build());

        when(adapterFactory.create(TargetType.AWS_ACM)).thenReturn(discoveryAdapter);
        when(discoveryAdapter.discover(message)).thenReturn(discovered);

        processor.process(message, context);

        ArgumentCaptor<CertDiscoveryResponse> responseCaptor =
                ArgumentCaptor.forClass(CertDiscoveryResponse.class);
        verify(sender).sendDiscoveryResponse(responseCaptor.capture());
        verify(context).complete();

        CertDiscoveryResponse response = responseCaptor.getValue();
        assertThat(response.getRequestId()).isEqualTo("req-test-001");
        assertThat(response.getOrganizationId()).isEqualTo("org-123");
        assertThat(response.getTargetType()).isEqualTo(TargetType.AWS_ACM);
        assertThat(response.getStatus()).isEqualTo("SUCCESS");
        assertThat(response.getDiscoveredCerts()).hasSize(1);
        DiscoveredCertEntry entry = response.getDiscoveredCerts().get(0);
        assertThat(entry.getDomain()).isEqualTo("test.example.net");
        assertThat(entry.getSubjectDn()).isEqualTo("CN=test.example.net,O=CertPing Test");
        assertThat(entry.getKeyUsage()).isEqualTo("DIGITAL_SIGNATURE,KEY_ENCIPHERMENT");
        assertThat(entry.getCertType()).isEqualTo("IMPORTED");
        assertThat(response.getRespondedAt()).isNotNull();
        assertThat(response.getBatchIndex()).isZero();
        assertThat(response.getTotalBatches()).isEqualTo(1);
    }

    @Test
    void process_emptyDiscovery_sendsSuccessResponseWithEmptyList() {
        CertDiscoveryMessage message = buildMessage();
        when(adapterFactory.create(TargetType.AWS_ACM)).thenReturn(discoveryAdapter);
        when(discoveryAdapter.discover(message)).thenReturn(List.of());

        processor.process(message, context);

        ArgumentCaptor<CertDiscoveryResponse> responseCaptor =
                ArgumentCaptor.forClass(CertDiscoveryResponse.class);
        verify(sender).sendDiscoveryResponse(responseCaptor.capture());
        verify(context).complete();

        CertDiscoveryResponse response = responseCaptor.getValue();
        assertThat(response.getDiscoveredCerts()).isEmpty();
        assertThat(response.getStatus()).isEqualTo("SUCCESS");
        assertThat(response.getBatchIndex()).isZero();
        assertThat(response.getTotalBatches()).isEqualTo(1);
    }

    @Test
    void process_largeScan_sendsMultipleBatchedResponses() {
        CertDiscoveryMessage message = buildMessage();
        // 130 certs → ceil(130/50) = 3 batches: 50, 50, 30
        List<DiscoveredCertEntry> discovered = buildDiscoveredEntries(130);

        when(adapterFactory.create(TargetType.AWS_ACM)).thenReturn(discoveryAdapter);
        when(discoveryAdapter.discover(message)).thenReturn(discovered);

        processor.process(message, context);

        ArgumentCaptor<CertDiscoveryResponse> responseCaptor =
                ArgumentCaptor.forClass(CertDiscoveryResponse.class);
        verify(sender, times(3)).sendDiscoveryResponse(responseCaptor.capture());
        verify(context).complete();

        List<CertDiscoveryResponse> responses = responseCaptor.getAllValues();
        assertThat(responses).hasSize(3);

        assertThat(responses.get(0).getBatchIndex()).isZero();
        assertThat(responses.get(0).getTotalBatches()).isEqualTo(3);
        assertThat(responses.get(0).getDiscoveredCerts()).hasSize(50);

        assertThat(responses.get(1).getBatchIndex()).isEqualTo(1);
        assertThat(responses.get(1).getTotalBatches()).isEqualTo(3);
        assertThat(responses.get(1).getDiscoveredCerts()).hasSize(50);

        assertThat(responses.get(2).getBatchIndex()).isEqualTo(2);
        assertThat(responses.get(2).getTotalBatches()).isEqualTo(3);
        assertThat(responses.get(2).getDiscoveredCerts()).hasSize(30);

        responses.forEach(r -> {
            assertThat(r.getStatus()).isEqualTo("SUCCESS");
            assertThat(r.getRequestId()).isEqualTo("req-test-001");
            assertThat(r.getOrganizationId()).isEqualTo("org-123");
            assertThat(r.getRespondedAt()).isNotNull();
        });
    }

    @Test
    void process_exactBatchBoundary_sendsCorrectNumberOfMessages() {
        CertDiscoveryMessage message = buildMessage();
        // Exactly 100 certs → 2 batches of 50
        List<DiscoveredCertEntry> discovered = buildDiscoveredEntries(100);

        when(adapterFactory.create(TargetType.AWS_ACM)).thenReturn(discoveryAdapter);
        when(discoveryAdapter.discover(message)).thenReturn(discovered);

        processor.process(message, context);

        verify(sender, times(2)).sendDiscoveryResponse(any());
        verify(context).complete();
    }

    @Test
    void process_kubernetesDiscovery_batchesAtTenCertificates() {
        CertDiscoveryMessage message = buildKubernetesMessage();
        List<DiscoveredCertEntry> discovered = buildDiscoveredEntries(25);

        when(adapterFactory.create(TargetType.KUBERNETES_SECRETS)).thenReturn(discoveryAdapter);
        when(discoveryAdapter.discover(message)).thenReturn(discovered);

        processor.process(message, context);

        ArgumentCaptor<CertDiscoveryResponse> responseCaptor =
                ArgumentCaptor.forClass(CertDiscoveryResponse.class);
        verify(sender, times(3)).sendDiscoveryResponse(responseCaptor.capture());
        verify(context).complete();

        List<CertDiscoveryResponse> responses = responseCaptor.getAllValues();
        assertThat(responses).extracting(response -> response.getDiscoveredCerts().size())
                .containsExactly(10, 10, 5);
        assertThat(responses).allSatisfy(response -> {
            assertThat(response.getTargetType()).isEqualTo(TargetType.KUBERNETES_SECRETS);
            assertThat(response.getTotalBatches()).isEqualTo(3);
        });
    }

    @Test
    void process_kubernetesDiscovery_splitsOversizedBatchBeforeSending() {
        CertDiscoveryMessage message = buildKubernetesMessage();
        List<DiscoveredCertEntry> discovered = buildDiscoveredEntriesWithUsagePayload(11, 30_000);

        when(adapterFactory.create(TargetType.KUBERNETES_SECRETS)).thenReturn(discoveryAdapter);
        when(discoveryAdapter.discover(message)).thenReturn(discovered);

        processor.process(message, context);

        ArgumentCaptor<CertDiscoveryResponse> responseCaptor =
                ArgumentCaptor.forClass(CertDiscoveryResponse.class);
        verify(sender, times(3)).sendDiscoveryResponse(responseCaptor.capture());
        verify(context).complete();

        assertThat(responseCaptor.getAllValues())
                .extracting(response -> response.getDiscoveredCerts().size())
                .containsExactly(5, 5, 1);
    }

    @Test
    void process_kubernetesDiscovery_singleOversizedCertificateFailsBeforeAnyResponseIsSent() {
        CertDiscoveryMessage message = buildKubernetesMessage();
        List<DiscoveredCertEntry> discovered = buildDiscoveredEntriesWithUsagePayload(1, 260_000);

        when(adapterFactory.create(TargetType.KUBERNETES_SECRETS)).thenReturn(discoveryAdapter);
        when(discoveryAdapter.discover(message)).thenReturn(discovered);

        assertThatThrownBy(() -> processor.process(message, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_RESPONSE_TOO_LARGE"));

        verify(sender, never()).sendDiscoveryResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_unsupportedTargetType_throwsPermanentExceptionAndDoesNotComplete() {
        CertDiscoveryMessage message = buildMessage();
        when(adapterFactory.create(TargetType.AWS_ACM))
                .thenThrow(new PermanentAgentException("DISCOVERY_UNSUPPORTED_TARGET", "No adapter"));

        assertThatThrownBy(() -> processor.process(message, context))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_UNSUPPORTED_TARGET"));

        verify(sender, never()).sendDiscoveryResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_adapterThrows_propagatesExceptionAndDoesNotComplete() {
        CertDiscoveryMessage message = buildMessage();
        when(adapterFactory.create(TargetType.AWS_ACM)).thenReturn(discoveryAdapter);
        when(discoveryAdapter.discover(message))
                .thenThrow(new PermanentAgentException("DISCOVERY_ACM_ACCESS_DENIED", "Denied"));

        assertThatThrownBy(() -> processor.process(message, context))
                .isInstanceOf(PermanentAgentException.class);

        verify(sender, never()).sendDiscoveryResponse(any());
        verify(context, never()).complete();
    }

    private List<DiscoveredCertEntry> buildDiscoveredEntries(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> DiscoveredCertEntry.builder()
                        .resourceId("arn:aws:acm:us-east-1:123:certificate/cert-" + i)
                        .domain("cert-" + i + ".example.com")
                        .certStatus("ISSUED")
                        .build())
                .collect(Collectors.toList());
    }

    private List<DiscoveredCertEntry> buildDiscoveredEntriesWithUsagePayload(int count, int payloadBytes) {
        String payload = "x".repeat(payloadBytes);
        return IntStream.range(0, count)
                .mapToObj(i -> DiscoveredCertEntry.builder()
                        .resourceId("k8s://prod/frontend/secrets/cert-" + i)
                        .domain("cert-" + i + ".example.com")
                        .certStatus("ISSUED")
                        .inUseBy(List.of("frontend/Ingress/api-" + i + "/" + payload))
                        .build())
                .collect(Collectors.toList());
    }

    private CertDiscoveryMessage buildMessage() {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setRequestId("req-test-001");
        msg.setCorrelationId("corr-test-001");
        msg.setOrganizationId("org-123");
        msg.setTargetType(TargetType.AWS_ACM);
        msg.setDeploymentCredHandle("https://kv-test.vault.azure.net/secrets/aws-cred");
        msg.setRequestedAt("2026-05-05T00:00:00Z");
        return msg;
    }

    private CertDiscoveryMessage buildKubernetesMessage() {
        CertDiscoveryMessage msg = buildMessage();
        msg.setTargetType(TargetType.KUBERNETES_SECRETS);
        msg.setCredentialScopeJson("{\"authProvider\":\"AZURE\",\"clusterName\":\"prod-aks\",\"namespaces\":[\"frontend\"]}");
        return msg;
    }
}
