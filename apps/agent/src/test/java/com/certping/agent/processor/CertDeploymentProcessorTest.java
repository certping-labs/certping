// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.DeploymentService;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertDeploymentProcessorTest {

    @Mock private DeploymentService               deploymentService;
    @Mock private AgentMessageSender              sender;
    @Mock private InboundContext context;

    private CertDeploymentProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new CertDeploymentProcessor(deploymentService, sender);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void process_success_sendsResponseAndCompletesMessage() {
        when(deploymentService.deploy(any())).thenReturn(
                DeploymentResult.of("https://kv.vault.azure.net/certificates/prod-tls/v1"));

        processor.process(buildMessage(), context);

        verify(sender).sendDeploymentResponse(any());
        verify(context).complete();
    }

    @Test
    void process_success_responseContainsDeploymentFields() {
        String targetResourceId = "https://kv.vault.azure.net/certificates/prod-tls/v1";
        when(deploymentService.deploy(any())).thenReturn(DeploymentResult.of(targetResourceId));

        processor.process(buildMessage(), context);

        ArgumentCaptor<com.certping.agent.model.message.CertDeploymentResponse> captor =
                ArgumentCaptor.forClass(com.certping.agent.model.message.CertDeploymentResponse.class);
        verify(sender).sendDeploymentResponse(captor.capture());

        var resp = captor.getValue();
        assertThat(resp.getStatus()).isEqualTo("SUCCESS");
        assertThat(resp.getTargetResourceId()).isEqualTo(targetResourceId);
        assertThat(resp.getOrganizationId()).isEqualTo("organization-1");
        assertThat(resp.getCertificateXref()).isEqualTo("xref-1");
        assertThat(resp.getRespondedAt()).isNotNull();
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    @Test
    void process_deploymentFails_rethrowsTransientAndSkipsSend() {
        RuntimeException boom = new TransientAgentException("DEPLOY_ERROR", "azure down");
        when(deploymentService.deploy(any())).thenThrow(boom);

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isSameAs(boom);

        verify(sender, never()).sendDeploymentResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_deploymentFails_rethrowsPermanentException() {
        PermanentAgentException boom = new PermanentAgentException("DEPLOY_ACCESS_DENIED", "403");
        when(deploymentService.deploy(any())).thenThrow(boom);

        assertThatThrownBy(() -> processor.process(buildMessage(), context))
                .isInstanceOf(PermanentAgentException.class);

        verify(sender, never()).sendDeploymentResponse(any());
        verify(context, never()).complete();
    }

    @Test
    void process_nullTargetType_stillProcesses() {
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetType(null);
        when(deploymentService.deploy(any())).thenReturn(
                DeploymentResult.of("https://kv.vault.azure.net/certificates/prod-tls/v1"));

        processor.process(msg, context);

        verify(sender).sendDeploymentResponse(any());
        verify(context).complete();
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-3");
        msg.setCorrelationId("corr-3");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AZURE_KV);
        msg.setDeploymentCredHandle("https://kv.vault.azure.net/secrets/azure-deploy-spn");
        return msg;
    }
}
