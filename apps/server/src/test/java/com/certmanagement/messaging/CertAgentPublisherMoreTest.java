// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.InboundSenders;
import com.certmanagement.messaging.transport.TransportProperties;
import com.certmanagement.dto.cert.IssueManualRequest;
import com.certmanagement.entity.CertManualIssuanceStateEntity;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.messaging.model.AgentDeepHealthCheckCommand;
import com.certmanagement.messaging.model.CertDeploymentCommand;
import com.certmanagement.messaging.model.CertDiscoveryCommand;
import com.certmanagement.messaging.model.CertIssuanceCommand;
import com.certmanagement.messaging.model.CertOwnSecretDeleteCommand;
import com.certmanagement.messaging.model.CertRenewalCommand;
import com.certmanagement.messaging.model.CertRevocationCommand;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.iot.messaging.DeviceIdentitySyncCommand;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Exercises the publish* paths of {@link CertAgentPublisher} with a mocked (INLINE — final class)
 * {@link MessageSender}, covering serialization, application-property stamping, queue
 * routing, manual-flow command building, blank-org guards, and the serialization-failure wrap.
 */
@ExtendWith(MockitoExtension.class)
class CertAgentPublisherMoreTest {

    @Mock private InboundSenders senderFactory;

    private TransportProperties transportProperties;
    private CertAgentPublisher    publisher;
    private MessageSender sender;

    @BeforeEach
    void setUp() {
        transportProperties = new TransportProperties();
        transportProperties.setInboundQueuePattern("{orgId}-agent-inbound");

        sender = mock(MessageSender.class);
        lenient().when(senderFactory.senderFor(anyString())).thenReturn(sender);

        publisher = new CertAgentPublisher(senderFactory, transportProperties, JsonMapper.builderWithJackson2Defaults().build());
    }

    @AfterEach
    void tearDown() {
        MDC.clear();
    }

    private TransportMessage captureSent() {
        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(captor.capture());
        return captor.getValue();
    }

    private CertificateEntity buildCert() {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(2L)
                .organizationId(42L)
                .domain("example.com")
                .build();
        return CertificateEntity.builder()
                .id(7L)
                .certificateXref("cert-xref-1")
                .userDomainCert(udc)
                .acmeAccountHandle("acme/path")
                .certSecretHandle("kv/path")
                .wildcard(false)
                .san(false)
                .build();
    }

    @Test
    void publishDiscoveryCommand_setsTheConfiguredTimeToLive() {
        transportProperties.setDiscoveryCommandTtl(java.time.Duration.ofMinutes(45));
        com.certmanagement.messaging.model.CertDiscoveryCommand cmd =
                com.certmanagement.messaging.model.CertDiscoveryCommand.builder()
                        .organizationId("42").orgType("B2B").requestId("req-d").targetType("AZURE_KV").build();

        publisher.publishDiscoveryCommand(cmd);

        org.assertj.core.api.Assertions.assertThat(captureSent().getTimeToLive())
                .isEqualTo(java.time.Duration.ofMinutes(45));
    }

    @Test
    void discoveryCommandTtl_defaultsToOneHour() {
        org.assertj.core.api.Assertions.assertThat(new TransportProperties().getDiscoveryCommandTtl())
                .isEqualTo(java.time.Duration.ofHours(1));
    }

    // --------------------------------------------------------------- //
    //  publishIssuance / Renewal / Deployment / Revocation
    // --------------------------------------------------------------- //

    @Test
    void publishIssuance_b2bOrg_sendsToPerOrgQueueWithProps() {
        CertIssuanceCommand cmd = CertIssuanceCommand.builder()
                .organizationId("42").orgType("B2B").requestId("req-1")
                .certificateXref("cert-1").domain("example.com")
                .build();

        publisher.publishIssuance(cmd);

        verify(senderFactory).senderFor("42-agent-inbound");
        TransportMessage msg = captureSent();
        assertThat(msg.getApplicationProperties()).containsEntry("MessageType", "CERT_ISSUANCE");
        assertThat(msg.getApplicationProperties()).containsEntry("organizationId", "42");
        assertThat(msg.getApplicationProperties()).containsEntry("requestId", "req-1");
        assertThat(msg.getBody().toString()).contains("cert-1");
    }

    @Test
    void publishIssuance_b2cOrg_routesToItsOwnQueue() {
        CertIssuanceCommand cmd = CertIssuanceCommand.builder()
                .organizationId("99").orgType("B2B").requestId("req-2")
                .certificateXref("cert-2").build();

        publisher.publishIssuance(cmd);

        verify(senderFactory).senderFor("99-agent-inbound");
    }

    @Test
    void publishRenewal_sendsRenewalMessageType() {
        CertRenewalCommand cmd = CertRenewalCommand.builder()
                .organizationId("42").orgType("B2B").requestId("req-3")
                .certificateXref("cert-3").build();

        publisher.publishRenewal(cmd);

        TransportMessage msg = captureSent();
        assertThat(msg.getApplicationProperties()).containsEntry("MessageType", "CERT_RENEWAL");
        assertThat(msg.getTimeToLive()).isEqualTo(CertAgentPublisher.RENEWAL_TIME_TO_LIVE);
    }

    @Test
    void publishIssuance_keepsTheQueueDefaultTimeToLive() {
        publisher.publishIssuance(CertIssuanceCommand.builder()
                .organizationId("42").orgType("B2B").requestId("req-5").certificateXref("cert-5").build());

        assertThat(captureSent().getTimeToLive()).isNull();
    }

    @Test
    void publishDeployment_sendsDeploymentMessageType() {
        CertDeploymentCommand cmd = CertDeploymentCommand.builder()
                .organizationId("42").orgType("B2B").requestId("req-4")
                .certificateXref("cert-4").targetType(TargetType.AZURE_KV).build();

        publisher.publishDeployment(cmd);

        assertThat(captureSent().getApplicationProperties()).containsEntry("MessageType", "CERT_DEPLOYMENT");
    }

    @Test
    void publishRevocationCommand_sendsRevocationMessageType() {
        CertRevocationCommand cmd = CertRevocationCommand.builder()
                .organizationId("42").orgType("B2B").requestId("req-5")
                .certificateXref("cert-5").build();

        publisher.publishRevocationCommand(cmd);

        assertThat(captureSent().getApplicationProperties()).containsEntry("MessageType", "CERT_REVOCATION_COMMAND");
    }

    @Test
    void publishKvSecretDeleteCommand_sendsKvSecretDeleteMessageType() {
        CertOwnSecretDeleteCommand cmd = CertOwnSecretDeleteCommand.builder()
                .organizationId("42").orgType("B2B").requestId("req-6")
                .certificateXref("cert-6").reason("EXPIRED").build();

        publisher.publishKvSecretDeleteCommand(cmd);

        assertThat(captureSent().getApplicationProperties()).containsEntry("MessageType", "CERT_OWN_SECRET_DELETE");
    }

    @Test
    void publishHeartbeatCadenceUpdate_buildsCommandAndSends() {
        publisher.publishHeartbeatCadenceUpdate("42", "B2B", 15);

        TransportMessage msg = captureSent();
        assertThat(msg.getApplicationProperties()).containsEntry("MessageType", "AGENT_HEARTBEAT_CADENCE_UPDATE");
        assertThat(msg.getBody().toString()).contains("15");
    }

    @Test
    void publishDeepHealthCheck_sendsDeepHealthMessageType() {
        AgentDeepHealthCheckCommand cmd = AgentDeepHealthCheckCommand.builder()
                .organizationId("42").orgType("B2B").requestId("req-7")
                .deepCheckId("deep-1").chunkIndex(0).totalChunks(1).build();

        publisher.publishDeepHealthCheck(cmd);

        assertThat(captureSent().getApplicationProperties()).containsEntry("MessageType", "AGENT_DEEP_HEALTH_CHECK");
    }

    @Test
    void publishDiscoveryCommand_sendsDiscoveryMessageType() {
        CertDiscoveryCommand cmd = CertDiscoveryCommand.builder()
                .organizationId("42").orgType("B2B").requestId("req-8")
                .targetType("KUBERNETES").build();

        publisher.publishDiscoveryCommand(cmd);

        assertThat(captureSent().getApplicationProperties()).containsEntry("MessageType", "CERT_DISCOVERY");
    }

    // --------------------------------------------------------------- //
    //  Manual flow
    // --------------------------------------------------------------- //

    @Test
    void publishManualTxtRequest_withSanEntries_buildsCommand() {
        IssueManualRequest.SanDomainEntry san = new IssueManualRequest.SanDomainEntry();
        san.setPatterns(List.of("*.example.com"));

        publisher.publishManualTxtRequest(buildCert(), "B2B", List.of(san), "req-9", "corr-9");

        verify(senderFactory).senderFor("42-agent-inbound");
        TransportMessage msg = captureSent();
        assertThat(msg.getApplicationProperties()).containsEntry("MessageType", "CERT_MANUAL_TXT_REQUEST");
        assertThat(msg.getBody().toString()).contains("example.com");
    }

    @Test
    void publishManualTxtRequest_nullSanEntries_sendsWithoutSanList() {
        publisher.publishManualTxtRequest(buildCert(), "B2B", null, "req-10", "corr-10");

        assertThat(captureSent().getApplicationProperties()).containsEntry("MessageType", "CERT_MANUAL_TXT_REQUEST");
    }

    @Test
    void publishManualTxtRequest_mdcOverload_usesMdcIds() {
        MDC.put("requestId", "mdc-req");
        MDC.put("correlationId", "mdc-corr");

        publisher.publishManualTxtRequest(buildCert(), "B2B", List.of());

        assertThat(captureSent().getApplicationProperties()).containsEntry("MessageType", "CERT_MANUAL_TXT_REQUEST");
    }

    @Test
    void publishManualDnsValidate_parsesTxtRecordsAndSends() {
        CertManualIssuanceStateEntity state = CertManualIssuanceStateEntity.builder()
                .acmeAccountHandle("acme/path")
                .acmeOrderUrl("https://acme/order/1")
                .txtRecords("[{\"recordName\":\"_acme-challenge.example.com\","
                        + "\"recordValue\":\"digest\",\"domain\":\"example.com\"}]")
                .build();

        publisher.publishManualDnsValidate(buildCert(), "B2B", state, "req-11", "corr-11");

        TransportMessage msg = captureSent();
        assertThat(msg.getApplicationProperties()).containsEntry("MessageType", "CERT_MANUAL_DNS_VALIDATE");
        assertThat(msg.getBody().toString()).contains("_acme-challenge.example.com");
    }

    @Test
    void publishManualDnsValidate_malformedTxtRecords_throws() {
        CertManualIssuanceStateEntity state = CertManualIssuanceStateEntity.builder()
                .txtRecords("not-json")
                .build();

        assertThatThrownBy(() -> publisher.publishManualDnsValidate(buildCert(), "B2B", state, "r", "c"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to deserialize txtRecords");
    }

    @Test
    void publishManualDnsValidate_withSanDomains_includesSanEntries() {
        CertificateEntity cert = buildCert();
        cert.setSanDomains(new String[]{"*.example.com"});
        CertManualIssuanceStateEntity state = CertManualIssuanceStateEntity.builder()
                .txtRecords("[]")
                .build();

        publisher.publishManualDnsValidate(cert, "B2B", state, "req-12", "corr-12");

        assertThat(captureSent().getApplicationProperties()).containsEntry("MessageType", "CERT_MANUAL_DNS_VALIDATE");
    }

    // --------------------------------------------------------------- //
    //  publishKvDeleteCommand guard + happy path
    // --------------------------------------------------------------- //

    @Test
    void publishKvDeleteCommand_blankXref_skipsSend() {
        publisher.publishKvDeleteCommand("  ", "kv/path", "42", "B2B");
        verify(senderFactory, never()).senderFor(anyString());
    }

    @Test
    void publishKvDeleteCommand_nullOrgId_skipsSend() {
        publisher.publishKvDeleteCommand("cert-x", "kv/path", null, "B2B");
        verify(senderFactory, never()).senderFor(anyString());
    }

    @Test
    void publishKvDeleteCommand_validInputs_sends() {
        publisher.publishKvDeleteCommand("cert-x", "kv/path", "42", "B2B");

        TransportMessage msg = captureSent();
        assertThat(msg.getApplicationProperties()).containsEntry("MessageType", "CERT_SECRET_DELETE_COMMAND");
        assertThat(msg.getBody().toString()).contains("cert-x");
    }

    @Test
    void deviceSyncUsesSyncXrefAsStableBrokerMessageId() {
        DeviceIdentitySyncCommand command = DeviceIdentitySyncCommand.builder()
                .organizationId("42")
                .orgType("B2B")
                .requestId("request-1")
                .sourceXref("source-1")
                .connectionProfileRef("intune-primary")
                .provider("INTUNE")
                .syncXref("sync-stable-1")
                .mode("FULL")
                .build();

        publisher.publishDeviceIdentitySyncCommand(command);

        TransportMessage message = captureSent();
        assertThat(message.getMessageId()).isEqualTo("sync-stable-1");
        assertThat(message.getApplicationProperties())
                .containsEntry("MessageType", "DEVICE_IDENTITY_SYNC_COMMAND")
                .doesNotContainKey("TargetAgentTokenId");
    }

    @Test
    void deviceSyncGoesToTheAgentThatAdvertisedTheSource() {
        AgentTargets targets = mock(AgentTargets.class);
        when(targets.forSource("42", "source-1")).thenReturn(7L);
        publisher = new CertAgentPublisher(senderFactory, transportProperties,
                JsonMapper.builderWithJackson2Defaults().build(), targets);

        publisher.publishDeviceIdentitySyncCommand(DeviceIdentitySyncCommand.builder()
                .organizationId("42").orgType("B2B").requestId("request-1").sourceXref("source-1")
                .connectionProfileRef("intune-primary").provider("INTUNE").syncXref("sync-2").mode("FULL")
                .build());

        assertThat(captureSent().getApplicationProperties()).containsEntry("TargetAgentTokenId", "7");
    }

    // --------------------------------------------------------------- //
    //  sendToInbound guard
    // --------------------------------------------------------------- //

    @Test
    void publish_blankOrganizationId_throwsIllegalArgument() {
        CertIssuanceCommand cmd = CertIssuanceCommand.builder()
                .organizationId("").orgType("B2B").requestId("req-13").build();

        assertThatThrownBy(() -> publisher.publishIssuance(cmd))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("organizationId must be set");
    }

    @Test
    void publish_nullOrganizationId_throwsIllegalArgument() {
        CertRenewalCommand cmd = CertRenewalCommand.builder()
                .organizationId(null).orgType("B2B").requestId("req-14").build();

        assertThatThrownBy(() -> publisher.publishRenewal(cmd))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
