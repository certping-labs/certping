// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.TransportMessage;
import com.certping.agent.transport.MessageSender;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.*;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import java.lang.reflect.Modifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.core.JacksonException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AgentMessageSenderTest {

    @Mock private MessageSender outboundSenderClient;

    private AgentMessageSender sender;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
        sender = new AgentMessageSender(outboundSenderClient, objectMapper);
    }

    // ── sendIssuanceResponse ──────────────────────────────────────────────────

    @Test
    void sendIssuanceResponse_sendsToOutboundWithCorrectMessageType() {
        sender.sendIssuanceResponse(buildIssuanceResponse());

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("CERT_ISSUANCE_RESPONSE");
    }

    @Test
    void sendIssuanceResponse_serialisesResponseBody() {
        sender.sendIssuanceResponse(buildIssuanceResponse());

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getBody().toString()).contains("ISSUED");
    }

    // ── sendDeploymentResponse ────────────────────────────────────────────────

    @Test
    void sendDeploymentResponse_sendsToOutboundWithCorrectMessageType() {
        sender.sendDeploymentResponse(buildDeploymentResponse());

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("CERT_DEPLOYMENT_RESPONSE");
    }

    @Test
    void sendRevocationResponse_sendsToOutboundWithCorrectMessageType() {
        sender.sendRevocationResponse(buildRevocationResponse());

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("CERT_REVOCATION_RESPONSE");
    }

    @Test
    void sendRevocationResponse_serialisesReasonAndXref() {
        sender.sendRevocationResponse(buildRevocationResponse());

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        String json = captor.getValue().getBody().toString();
        assertThat(json).contains("KEY_COMPROMISE");
        assertThat(json).contains("xref-1");
    }

    @Test
    void sendManualTxtResponse_sendsToOutboundWithCorrectMessageType() {
        CertManualTxtResponse response = CertManualTxtResponse.builder()
                .requestId("req-m1")
                .correlationId("corr-m1")
                .organizationId("organization-1")
                .certificateXref("xref-1")
                .build();

        sender.sendManualTxtResponse(response);

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("CERT_MANUAL_TXT_RESPONSE");
    }

    @Test
    void sendManualTxtResponse_serialisesCorrelationFieldsInBody() {
        CertManualTxtResponse response = CertManualTxtResponse.builder()
                .requestId("req-m1")
                .correlationId("corr-m1")
                .organizationId("organization-1")
                .certificateXref("xref-1")
                .build();

        sender.sendManualTxtResponse(response);

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        String json = captor.getValue().getBody().toString();
        assertThat(json).contains("req-m1");
        assertThat(json).contains("corr-m1");
        assertThat(json).contains("organization-1");
    }

    // ── sendKvDeleteResponse ──────────────────────────────────────────────────

    @Test
    void sendKvDeleteResponse_sendsToOutboundWithCorrectMessageType() {
        CertSecretDeleteResponse response = CertSecretDeleteResponse.builder()
                .requestId("req-kv1")
                .correlationId("corr-kv1")
                .organizationId("org-1")
                .certificateXref("xref-1")
                .status("SUCCESS")
                .respondedAt("2026-05-01T00:00:00Z")
                .build();

        sender.sendKvDeleteResponse(response);

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("CERT_SECRET_DELETE_RESPONSE");
        assertThat(captor.getValue().getBody().toString()).contains("xref-1");
    }

    // ── sendAgentError ────────────────────────────────────────────────────────

    @Test
    void sendAgentError_sendsToOutboundWithCorrectMessageType() {
        AgentErrorMessage error = AgentErrorMessage.builder()
                .errorCode("TEST_ERROR")
                .errorDetail("test detail")
                .build();

        sender.sendAgentError(error);

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("AGENT_ERROR");
    }

    // ── error handling ────────────────────────────────────────────────────────

    @Test
    void send_asbThrowsRuntimeException_wrapsAsTransient() {
        doThrow(new RuntimeException("gateway connection lost")).when(outboundSenderClient).sendMessage(any());

        assertThatThrownBy(() -> sender.sendIssuanceResponse(buildIssuanceResponse()))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("SEND_FAILED"));
    }

    // ── uncovered send() helpers ──────────────────────────────────────────────

    @Test
    void sendHealthHeartbeat_setsCorrectMessageType() {
        AgentHealthHeartbeat hb = AgentHealthHeartbeat.builder()
                .organizationId("org-1")
                .listening(true)
                .build();

        sender.sendHealthHeartbeat(hb);

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("AGENT_HEALTH_HEARTBEAT");
    }

    @Test
    void sendDeepHealthCheckResponse_setsCorrectMessageType() {
        AgentDeepHealthCheckResponse resp = AgentDeepHealthCheckResponse.builder()
                .deepCheckId("dhc-1")
                .status("SUCCESS")
                .build();

        sender.sendDeepHealthCheckResponse(resp);

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("AGENT_DEEP_HEALTH_CHECK_RESPONSE");
    }

    @Test
    void sendDiscoveryResponse_setsCorrectMessageType() {
        CertDiscoveryResponse resp = CertDiscoveryResponse.builder()
                .requestId("req-1")
                .organizationId("org-1")
                .build();

        sender.sendDiscoveryResponse(resp);

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("CERT_DISCOVERY_RESPONSE");
    }

    @Test
    void sendDiscoveryComplete_setsCorrectMessageType() {
        CertDiscoveryCompleteMessage msg = CertDiscoveryCompleteMessage.builder()
                .requestId("req-1")
                .organizationId("org-1")
                .build();

        sender.sendDiscoveryComplete(msg);

        ArgumentCaptor<com.certping.agent.transport.TransportMessage> captor =
                ArgumentCaptor.forClass(com.certping.agent.transport.TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties().get("MessageType"))
                .isEqualTo("CERT_DISCOVERY_COMPLETE");
    }

    @Test
    void send_jsonProcessingException_wrappedAsPermanent() {
        // Force JsonProcessingException by using an ObjectMapper mock that throws.
        ObjectMapper broken = mock(ObjectMapper.class);
        try {
            when(broken.writeValueAsBytes(any()))
                    .thenThrow(new JacksonException("boom") {});
        } catch (Exception ignored) {}
        AgentMessageSender brokenSender = new AgentMessageSender(outboundSenderClient, broken);

        assertThatThrownBy(() -> brokenSender.sendIssuanceResponse(buildIssuanceResponse()))
                .isInstanceOf(com.certping.agent.exception.PermanentAgentException.class)
                .satisfies(e -> assertThat(
                        ((com.certping.agent.exception.PermanentAgentException) e).getErrorCode())
                        .isEqualTo("SERIALIZATION_FAILED"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CertIssuanceResponse buildIssuanceResponse() {
        return CertIssuanceResponse.builder()
                .requestId("req-1")
                .correlationId("corr-1")
                .organizationId("organization-1")
                .certificateXref("xref-1")
                .status("ISSUED")
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1")
                .build();
    }

    private CertDeploymentResponse buildDeploymentResponse() {
        return CertDeploymentResponse.builder()
                .requestId("req-3")
                .correlationId("corr-3")
                .organizationId("organization-1")
                .certificateXref("xref-1")
                .targetType(TargetType.AZURE_KV)
                .status("SUCCESS")
                .targetResourceId("https://kv.vault.azure.net/certificates/prod-tls/v1")
                .build();
    }

        private CertRevocationResponse buildRevocationResponse() {
                return CertRevocationResponse.builder()
                                .requestId("req-r1")
                                .correlationId("corr-r1")
                                .organizationId("organization-1")
                                .certificateXref("xref-1")
                                .caProvider(CaProvider.LETS_ENCRYPT)
                                .revocationReason("KEY_COMPROMISE")
                                .revokedAt("2026-01-01T00:00:00Z")
                                .build();
        }

    /**
     * Every public {@code send*} method, reflected rather than hand-listed so a new sender method
     * is covered automatically.
     */
    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> allSendMethods() {
        return java.util.Arrays.stream(AgentMessageSender.class.getDeclaredMethods())
                .filter(m -> Modifier.isPublic(m.getModifiers()))
                .filter(m -> m.getParameterCount() == 1)
                .filter(m -> m.getReturnType() == void.class)
                .filter(m -> m.getName().startsWith("send"))
                .map(m -> org.junit.jupiter.params.provider.Arguments.of(m.getName(), m.getParameterTypes()[0]));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allSendMethods")
    void everyPublicSendMethodCarriesOnlyTheMessageType(String methodName, Class<?> payloadType)
            throws Exception {
        // The agent token authenticates the message and the server stamps the organization from
        // it, so the agent adds no organization claim or signature of its own.
        Object payload = payloadType.getMethod("builder").invoke(null);
        payload = payload.getClass().getMethod("build").invoke(payload);

        AgentMessageSender.class.getMethod(methodName, payloadType).invoke(sender, payload);

        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(outboundSenderClient).sendMessage(captor.capture());
        assertThat(captor.getValue().getApplicationProperties())
                .as("%s application properties", methodName)
                .containsOnlyKeys("MessageType");
    }
}
