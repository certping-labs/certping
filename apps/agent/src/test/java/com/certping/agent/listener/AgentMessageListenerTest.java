// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.MessageBody;
import com.certping.agent.transport.InboundMessage;
import com.certping.agent.transport.InboundContext;
import com.certping.agent.transport.DeadLetterOptions;
import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.DuplicateDeliveryException;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.message.AgentErrorMessage;
import com.certping.agent.processor.CertDeploymentProcessor;
import com.certping.agent.processor.CertDiscoveryProcessor;
import com.certping.agent.processor.DeviceIdentitySyncProcessor;
import com.certping.agent.processor.IotDeviceSyncProcessor;
import com.certping.agent.processor.CertIssuanceProcessor;
import com.certping.agent.processor.AgentDeepHealthCheckProcessor;
import com.certping.agent.processor.AgentHeartbeatCadenceProcessor;
import com.certping.agent.processor.CertSecretDeleteProcessor;
import com.certping.agent.processor.CertManualIssuanceProcessor;
import com.certping.agent.processor.CertRenewalProcessor;
import com.certping.agent.processor.CertOwnSecretDeleteProcessor;
import com.certping.agent.processor.CertRevocationProcessor;
import com.certping.agent.processor.CertificateProfileProcessor;
import com.certping.agent.processor.CertificateProfileSyncProcessor;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.time.OffsetDateTime;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AgentMessageListenerTest {

    @Mock private AgentMessageSender sender;
    @Mock private CertIssuanceProcessor issuanceProcessor;
    @Mock private CertRenewalProcessor renewalProcessor;
    @Mock private CertDeploymentProcessor deploymentProcessor;
    @Mock private CertManualIssuanceProcessor manualIssuanceProcessor;
    @Mock private CertRevocationProcessor certRevocationProcessor;
    @Mock private CertOwnSecretDeleteProcessor certKvSecretDeleteProcessor;
    @Mock private AgentHeartbeatCadenceProcessor cadenceProcessor;
    @Mock private AgentDeepHealthCheckProcessor deepHealthCheckProcessor;
    @Mock private CertSecretDeleteProcessor certKvDeleteProcessor;
    @Mock private CertDiscoveryProcessor certDiscoveryProcessor;
    @Mock private DeviceIdentitySyncProcessor deviceIdentitySyncProcessor;
    @Mock private IotDeviceSyncProcessor iotDeviceSyncProcessor;
    @Mock private com.certping.agent.processor.IotCertificateRevocationProcessor iotCertificateRevocationProcessor;
    @Mock private com.certping.agent.processor.IotIntuneRevocationProcessor iotIntuneRevocationProcessor;
    @Mock private CertificateProfileProcessor certificateProfileProcessor;
    @Mock private CertificateProfileSyncProcessor certificateProfileSyncProcessor;
    @Mock private ScheduledRetryService scheduledRetryService;
    @Mock private CheckpointStagingPurger checkpointStagingPurger;
    @Mock private AttemptRecords attemptRecords;
    @Mock private InboundContext context;
    @Mock private InboundMessage message;

    private AgentMessageListener listener;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("organization-1");
        listener = new AgentMessageListener(
                objectMapper, new AgentInboundMessageRouting(properties), scheduledRetryService, sender,
                issuanceProcessor, renewalProcessor, deploymentProcessor,
                manualIssuanceProcessor, certRevocationProcessor, certKvSecretDeleteProcessor,
                cadenceProcessor, deepHealthCheckProcessor, certKvDeleteProcessor,
                certDiscoveryProcessor, deviceIdentitySyncProcessor, iotDeviceSyncProcessor,
                iotCertificateRevocationProcessor, iotIntuneRevocationProcessor,
                certificateProfileProcessor, certificateProfileSyncProcessor,
                new SimpleMeterRegistry(), checkpointStagingPurger, attemptRecords);

        lenient().when(context.getMessage()).thenReturn(message);
        lenient().when(scheduledRetryService.slotFor(any(), any())).thenAnswer(invocation -> Optional.of(
                new ScheduledRetryService.RetrySlot(invocation.getArgument(1), OffsetDateTime.now(), Duration.ofHours(1))));
        lenient().when(message.getMessageId()).thenReturn(UUID.randomUUID().toString());
    }

    // ── Routing ──────────────────────────────────────────────────────────────

    @Test
    void onMessage_certIssuance_routesToIssuanceProcessor() {
        givenMessageType("CERT_ISSUANCE");
        givenBody(certIssuanceJson());

        listener.onMessage(context);

        verify(issuanceProcessor).process(any(), eq(context));
        verify(renewalProcessor, never()).process(any(), any());
        verify(deploymentProcessor, never()).process(any(), any());
        verify(manualIssuanceProcessor, never()).processManualTxtRequest(any(), any());
        verify(manualIssuanceProcessor, never()).processManualDnsValidation(any(), any());
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_certRenewal_routesToRenewalProcessor() {
        givenMessageType("CERT_RENEWAL");
        givenBody(certRenewalJson());

        listener.onMessage(context);

        verify(renewalProcessor).process(any(), eq(context));
        verify(issuanceProcessor, never()).process(any(), any());
        verify(manualIssuanceProcessor, never()).processManualTxtRequest(any(), any());
        verify(manualIssuanceProcessor, never()).processManualDnsValidation(any(), any());
    }

    @Test
    void onMessage_certDeployment_routesToDeploymentProcessor() {
        givenMessageType("CERT_DEPLOYMENT");
        givenBody(certDeploymentJson());

        listener.onMessage(context);

        verify(deploymentProcessor).process(any(), eq(context));
        verify(issuanceProcessor, never()).process(any(), any());
        verify(manualIssuanceProcessor, never()).processManualTxtRequest(any(), any());
        verify(manualIssuanceProcessor, never()).processManualDnsValidation(any(), any());
    }

    @Test
    void onMessage_certManualTxtRequest_routesToManualTxtRequestHandler() {
        givenMessageType("CERT_MANUAL_TXT_REQUEST");
        givenBody(certManualTxtRequestJson());

        listener.onMessage(context);

        verify(manualIssuanceProcessor).processManualTxtRequest(any(), eq(context));
        verify(manualIssuanceProcessor, never()).processManualDnsValidation(any(), any());
        verify(issuanceProcessor, never()).process(any(), any());
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_certManualDnsValidate_routesToManualDnsValidationHandler() {
        givenMessageType("CERT_MANUAL_DNS_VALIDATE");
        givenBody(certManualValidateJson());

        listener.onMessage(context);

        verify(manualIssuanceProcessor).processManualDnsValidation(any(), eq(context));
        verify(manualIssuanceProcessor, never()).processManualTxtRequest(any(), any());
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_certRevocationCommand_routesToRevocationProcessor() {
        givenMessageType("CERT_REVOCATION_COMMAND");
        givenBody(certRevocationJson());

        listener.onMessage(context);

        verify(certRevocationProcessor).process(any(), eq(context));
        verify(issuanceProcessor, never()).process(any(), any());
        verify(renewalProcessor, never()).process(any(), any());
        verify(deploymentProcessor, never()).process(any(), any());
        verify(manualIssuanceProcessor, never()).processManualTxtRequest(any(), any());
        verify(manualIssuanceProcessor, never()).processManualDnsValidation(any(), any());
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_certKvSecretDelete_routesToKvDeleteProcessor() {
        givenMessageType("CERT_OWN_SECRET_DELETE");
        givenBody(certKvSecretDeleteJson());

        listener.onMessage(context);

        verify(certKvSecretDeleteProcessor).process(any(), eq(context));
        verify(issuanceProcessor, never()).process(any(), any());
    }

    @Test
    void onMessage_agentDeepHealthCheck_routesToDeepHealthProcessor() {
        givenMessageType("AGENT_DEEP_HEALTH_CHECK");
        givenBody(deepHealthCheckJson());

        listener.onMessage(context);

        verify(deepHealthCheckProcessor).process(any(), eq(context));
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_certKvDeleteCommand_routesToKvDeleteProcessor() {
        givenMessageType("CERT_SECRET_DELETE_COMMAND");
        givenBody(certKvDeleteJson());

        listener.onMessage(context);

        verify(certKvDeleteProcessor).process(any(), eq(context));
        verify(issuanceProcessor, never()).process(any(), any());
        verify(renewalProcessor, never()).process(any(), any());
        verify(deploymentProcessor, never()).process(any(), any());
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_certManualTxtResponse_outboundOnly_deadLetters() {
        givenMessageType("CERT_MANUAL_TXT_RESPONSE");
        givenBody("{}");

        listener.onMessage(context);

        verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(manualIssuanceProcessor, never()).processManualTxtRequest(any(), any());
        verify(manualIssuanceProcessor, never()).processManualDnsValidation(any(), any());
        ArgumentCaptor<AgentErrorMessage> errorCaptor = ArgumentCaptor.forClass(AgentErrorMessage.class);
        verify(sender).sendAgentError(errorCaptor.capture());
        assertThat(errorCaptor.getValue().getErrorCode()).isEqualTo("UNKNOWN_MESSAGE_TYPE");
        assertThat(errorCaptor.getValue().getErrorDetail())
                .contains("CERT_MANUAL_TXT_RESPONSE");
    }

    @Test
    void onMessage_transientError_schedulesRetry_withoutAgentError() {
        givenMessageType("CERT_DEPLOYMENT");
        givenBody(certDeploymentJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.scheduleRetry(eq(context), any(ScheduledRetryService.RetrySlot.class), eq("DEPLOY_APIGW_ERROR"), any(), any()))
                .thenReturn(true);

        doThrow(new TransientAgentException("DEPLOY_APIGW_ERROR", "Too Many Requests"))
                .when(deploymentProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(scheduledRetryService).scheduleRetry(eq(context), any(ScheduledRetryService.RetrySlot.class), eq("DEPLOY_APIGW_ERROR"), any(), any());
        verify(context, never()).abandon();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
        verify(sender, never()).sendAgentError(any());
    }

    @Test
    void onMessage_retryableError_withRetryAfter_schedulesRetry() {
        givenMessageType("CERT_ISSUANCE");
        givenBody(certIssuanceJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.scheduleRetry(eq(context), any(ScheduledRetryService.RetrySlot.class), eq("ACME_RATE_LIMITED"), any(), any()))
                .thenReturn(true);

        doThrow(new RetryableAgentException("ACME_RATE_LIMITED", "rate limited", Duration.ofHours(2)))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(scheduledRetryService).scheduleRetry(eq(context), any(ScheduledRetryService.RetrySlot.class), eq("ACME_RATE_LIMITED"), any(), any());
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_retryableError_scheduleFails_fallsBackToAbandon() {
        givenMessageType("CERT_DEPLOYMENT");
        givenBody(certDeploymentJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.scheduleRetry(eq(context), any(ScheduledRetryService.RetrySlot.class), any(), any(), any()))
                .thenReturn(false);

        doThrow(new TransientAgentException("DEPLOY_APIGW_ERROR", "Too Many Requests"))
                .when(deploymentProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(context).abandon();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_terminalDeviceSyncFailurePublishesFencedErrorWithoutRetry() {
        givenMessageType("DEVICE_IDENTITY_SYNC_COMMAND");
        givenBody(deviceIdentitySyncJson());
        doThrow(new PermanentAgentException("PLATFORM_THROTTLED", "Graph throttled"))
                .when(deviceIdentitySyncProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(scheduledRetryService, never()).scheduleRetry(any(), any(), any(), any(), any());
        verify(context).deadLetter(any(DeadLetterOptions.class));
        ArgumentCaptor<AgentErrorMessage> errorCaptor = ArgumentCaptor.forClass(AgentErrorMessage.class);
        verify(sender).sendAgentError(errorCaptor.capture());
        AgentErrorMessage error = errorCaptor.getValue();
        assertThat(error.getOriginalMessageType()).isEqualTo("DEVICE_IDENTITY_SYNC_COMMAND");
        assertThat(error.getOrganizationId()).isEqualTo("organization-1");
        assertThat(error.getSourceXref()).isEqualTo("source-1");
        assertThat(error.getSyncXref()).isEqualTo("sync-1");
        assertThat(error.getErrorCode()).isEqualTo("PLATFORM_THROTTLED");
    }

    @Test
    void onMessage_certificateProfileCommandRoutesToProfileProcessor() {
        givenMessageType("IOT_CERTIFICATE_PROFILE_COMMAND");
        givenBody("""
                {"requestId":"op-1","organizationId":"organization-1",
                 "sourceXref":"source-1","connectionProfileRef":"intune-primary",
                 "provider":"INTUNE","profileXref":"profile-1","operationXref":"op-1",
                 "operation":"CREATE","desiredRevision":1}
                """);

        listener.onMessage(context);

        verify(certificateProfileProcessor).process(any(), eq(context));
    }

    @Test
    void onMessage_certificateProfileSyncRoutesToProfileSyncProcessor() {
        givenMessageType("IOT_CERTIFICATE_PROFILE_SYNC_COMMAND");
        givenBody("""
                {"requestId":"profile-sync-1","organizationId":"organization-1",
                 "sourceXref":"source-1","connectionProfileRef":"intune-primary",
                 "provider":"INTUNE"}
                """);

        listener.onMessage(context);

        verify(certificateProfileSyncProcessor).process(any(), eq(context));
    }

    @Test
    void onMessage_retryBudgetExhausted_deadLetters_andPublishesAgentError() {
        givenMessageTypeWithRetryCount("CERT_DEPLOYMENT", 8);
        givenBody(certDeploymentJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));

        doThrow(new TransientAgentException("DEPLOY_APIGW_ERROR", "Too Many Requests"))
                .when(deploymentProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(scheduledRetryService, never()).scheduleRetry(any(), any(), any(), any(), any());
        verify(context, never()).abandon();
        ArgumentCaptor<DeadLetterOptions> dlqCaptor = ArgumentCaptor.forClass(DeadLetterOptions.class);
        verify(context).deadLetter(dlqCaptor.capture());
        assertThat(dlqCaptor.getValue().getDeadLetterReason()).isEqualTo("RETRY_GIVE_UP");
        ArgumentCaptor<AgentErrorMessage> errorCaptor = ArgumentCaptor.forClass(AgentErrorMessage.class);
        verify(sender).sendAgentError(errorCaptor.capture());
        assertThat(errorCaptor.getValue().getErrorCode()).isEqualTo("RETRY_GIVE_UP");
    }

    @Test
    void onMessage_paidCaOrderPastTheGlobalRetryCap_isScheduledAgain() {
        givenMessageTypeWithRetryCount("CERT_DEPLOYMENT", 40);
        givenBody(certDeploymentJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.scheduleRetry(any(), any(), any(), any(), any())).thenReturn(true);
        doThrow(new RetryableAgentException("CA_ORDER_PENDING", "not collected yet", Duration.ofMinutes(15)))
                .when(deploymentProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(scheduledRetryService).scheduleRetry(eq(context), any(), eq("CA_ORDER_PENDING"), any(), any());
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_paidCaOrderAtTheAbsoluteRetryCap_isDeadLettered() {
        givenMessageTypeWithRetryCount("CERT_DEPLOYMENT", 200);
        givenBody(certDeploymentJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        doThrow(new RetryableAgentException("CA_ORDER_PENDING", "not collected yet", Duration.ofMinutes(15)))
                .when(deploymentProcessor).process(any(), eq(context));

        listener.onMessage(context);

        ArgumentCaptor<DeadLetterOptions> dlqCaptor = ArgumentCaptor.forClass(DeadLetterOptions.class);
        verify(context).deadLetter(dlqCaptor.capture());
        assertThat(dlqCaptor.getValue().getDeadLetterReason()).isEqualTo("RETRY_GIVE_UP");
    }

    @Test
    void onMessage_aRetryThatWouldStartPastTheAttemptDeadline_givesUp() {
        givenMessageTypeWithRetryCount("CERT_DEPLOYMENT", 1);
        givenBody(certDeploymentJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.slotFor(eq(message), any(Duration.class))).thenReturn(Optional.empty());
        doThrow(new TransientAgentException("DEPLOY_APIGW_ERROR", "Too Many Requests"))
                .when(deploymentProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(scheduledRetryService, never()).scheduleRetry(any(), any(), any(), any(), any());
        ArgumentCaptor<DeadLetterOptions> dlqCaptor = ArgumentCaptor.forClass(DeadLetterOptions.class);
        verify(context).deadLetter(dlqCaptor.capture());
        assertThat(dlqCaptor.getValue().getDeadLetterReason()).isEqualTo("RETRY_GIVE_UP");
        verify(sender).sendAgentError(any());
    }

    @Test
    void onMessage_aStoredResultThatCannotBeSentInTime_isDeadLetteredWithoutAnAgentError() {
        givenMessageTypeWithRetryCount("CERT_ISSUANCE", 3);
        givenBody(certIssuanceJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.slotFor(eq(message), any(Duration.class))).thenReturn(Optional.empty());
        doThrow(new RetryableAgentException("RESPONSE_PUBLISH_FAILED", "bus down", null, null,
                IssuanceCheckpoint.storedResult("LETS_ENCRYPT", "{}")))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        ArgumentCaptor<DeadLetterOptions> dlqCaptor = ArgumentCaptor.forClass(DeadLetterOptions.class);
        verify(context).deadLetter(dlqCaptor.capture());
        assertThat(dlqCaptor.getValue().getDeadLetterReason()).isEqualTo("RESPONSE_PUBLISH_FAILED");
        verify(sender, never()).sendAgentError(any());
        verify(checkpointStagingPurger, never()).purgeIfPresent(any());
    }

    @Test
    void onMessage_aStoredResultWithTimeLeft_isScheduledAgainWithIt() {
        givenMessageTypeWithRetryCount("CERT_ISSUANCE", 3);
        givenBody(certIssuanceJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.scheduleRetry(any(), any(), any(), any(), any())).thenReturn(true);
        IssuanceCheckpoint stored = IssuanceCheckpoint.storedResult("LETS_ENCRYPT", "{}");
        doThrow(new RetryableAgentException("RESPONSE_PUBLISH_FAILED", "bus down", null, null, stored))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(scheduledRetryService).scheduleRetry(eq(context), any(), eq("RESPONSE_PUBLISH_FAILED"), any(),
                eq(stored));
        verify(sender, never()).sendAgentError(any());
    }

    @Test
    void onMessage_anOrderedAttempt_isRecordedBeforeItsRetryIsSent() {
        givenMessageTypeWithRetryCount("CERT_ISSUANCE", 1);
        givenBody(certIssuanceJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.scheduleRetry(any(), any(), any(), any(), any())).thenReturn(true);
        IssuanceCheckpoint ordered = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED, "999",
                null, "kv-staged");
        doThrow(new RetryableAgentException("CA_ORDER_PENDING", "not collected yet", null, null, ordered))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        InOrder order = inOrder(attemptRecords, scheduledRetryService);
        order.verify(attemptRecords).save(message, "xref-1", ordered);
        order.verify(scheduledRetryService).scheduleRetry(eq(context), any(), eq("CA_ORDER_PENDING"), any(),
                eq(ordered));
    }

    @Test
    void onMessage_aRetryWhoseAttemptCannotBeRecorded_isSentAnywayWithItsCheckpoint() {
        givenMessageTypeWithRetryCount("CERT_ISSUANCE", 1);
        givenBody(certIssuanceJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.scheduleRetry(any(), any(), any(), any(), any())).thenReturn(true);
        IssuanceCheckpoint ordered = new IssuanceCheckpoint("LETS_ENCRYPT", IssuanceCheckpoint.Step.ORDER_CREATED,
                "https://acme/order/1", "acct", "kv-staged");
        doThrow(new TransientAgentException("KV_WRITE_FAILED", "busy"))
                .when(attemptRecords).save(message, "xref-1", ordered);
        doThrow(new RetryableAgentException("ACME_ORDER_PENDING", "pending", null, null, ordered))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(scheduledRetryService).scheduleRetry(eq(context), any(), eq("ACME_ORDER_PENDING"), any(), eq(ordered));
        verify(context, never()).abandon();
    }

    @Test
    void onMessage_anAttemptGivenUp_isMarkedFailedBeforeItIsDeadLettered() {
        givenMessageTypeWithRetryCount("CERT_ISSUANCE", 3);
        givenBody(certIssuanceJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.slotFor(eq(message), any(Duration.class))).thenReturn(Optional.empty());
        doThrow(new TransientAgentException("DNS_API_ERROR", "down"))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        InOrder order = inOrder(attemptRecords, context);
        order.verify(attemptRecords).fail(message, "xref-1");
        order.verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(scheduledRetryService, never()).scheduleRetry(any(), any(), any(), any(), any());
    }

    @Test
    void onMessage_aStoredResultGivenUp_keepsItsRecordedResult() {
        givenMessageTypeWithRetryCount("CERT_ISSUANCE", 3);
        givenBody(certIssuanceJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.slotFor(eq(message), any(Duration.class))).thenReturn(Optional.empty());
        doThrow(new RetryableAgentException("RESPONSE_PUBLISH_FAILED", "bus down", null, null,
                IssuanceCheckpoint.storedResult("LETS_ENCRYPT", "{}")))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(attemptRecords, never()).fail(any(), any());
    }

    @Test
    void onMessage_aPermanentFailure_isMarkedFailedBeforeItIsDeadLettered() {
        givenMessageType("CERT_ISSUANCE");
        givenBody(certIssuanceJson());
        doThrow(new PermanentAgentException("CA_ORDER_REJECTED", "rejected"))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        InOrder order = inOrder(attemptRecords, context);
        order.verify(attemptRecords).fail(message, "xref-1");
        order.verify(context).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_aRetryThatCouldNotBeSettled_isRecordedAgainForTheRedelivery() {
        givenMessageTypeWithRetryCount("CERT_ISSUANCE", 1);
        givenBody(certIssuanceJson());
        when(scheduledRetryService.policy()).thenReturn(RetryPolicy.from(new AgentProperties.RetryProperties()));
        when(scheduledRetryService.scheduleRetry(any(), any(), any(), any(), any())).thenReturn(false);
        IssuanceCheckpoint ordered = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED, "999",
                null, "kv-staged");
        doThrow(new TransientAgentException("KV_WRITE_FAILED", "busy")).doNothing()
                .when(attemptRecords).save(message, "xref-1", ordered);
        doThrow(new RetryableAgentException("CA_ORDER_PENDING", "not collected yet", null, null, ordered))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(attemptRecords, times(2)).save(message, "xref-1", ordered);
        verify(context).abandon();
    }

    @Test
    void onMessage_aFailedAttemptThatCannotBeDeadLettered_isStillMarkedFailed() {
        givenMessageType("CERT_ISSUANCE");
        givenBody(certIssuanceJson());
        doThrow(new PermanentAgentException("CA_ORDER_REJECTED", "rejected"))
                .when(issuanceProcessor).process(any(), eq(context));
        doThrow(new IllegalStateException("lock lost")).when(context).deadLetter(any(DeadLetterOptions.class));

        listener.onMessage(context);

        verify(attemptRecords).fail(message, "xref-1");
    }

    @Test
    void onMessage_aDuplicateDelivery_isSettledWithoutAnErrorAndLeavesTheAttemptRecord() {
        givenMessageType("CERT_ISSUANCE");
        givenBody(certIssuanceJson());
        doThrow(new DuplicateDeliveryException("another delivery recorded its order"))
                .when(issuanceProcessor).process(any(), eq(context));

        listener.onMessage(context);

        verify(context).complete();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
        verify(context, never()).abandon();
        verify(sender, never()).sendAgentError(any());
        verify(attemptRecords, never()).fail(any(), any());
        verify(attemptRecords, never()).save(any(), any(), any());
        verify(scheduledRetryService, never()).scheduleRetry(any(), any(), any(), any(), any());
    }

    @Test
    void onMessage_organizationMismatch_completesAndSkipsProcessing() {
        givenMessageType("CERT_DEPLOYMENT");
        givenBody("""
                {
                  "requestId": "req-3",
                  "correlationId": "corr-3",
                  "organizationId": "other-org",
                  "certificateXref": "xref-1",
                  "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1",
                  "targetType": "AZURE_KV",
                  "certificateName": "prod-app-tls",
                  "deploymentCredentialPath": "https://kv.vault.azure.net/secrets/azure-spn"
                }
                """);
        when(context.getEntityPath()).thenReturn("cert-agent-inbound/Subscriptions/acme-inc-deployment");

        listener.onMessage(context);

        verify(deploymentProcessor, never()).process(any(), any());
        verify(context).complete();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void onMessage_missingOrganizationId_deadLettersInboundCommand() {
        givenMessageType("CERT_DEPLOYMENT");
        givenBody("""
                {
                  "requestId": "req-3",
                  "correlationId": "corr-3",
                  "certificateXref": "xref-1",
                  "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1",
                  "targetType": "AZURE_KV",
                  "certificateName": "prod-app-tls",
                  "deploymentCredentialPath": "https://kv.vault.azure.net/secrets/azure-spn"
                }
                """);
        when(context.getEntityPath()).thenReturn("cert-agent-inbound/Subscriptions/acme-inc-deployment");

        listener.onMessage(context);

        verify(deploymentProcessor, never()).process(any(), any());
        verify(context).deadLetter(any(DeadLetterOptions.class));
    }

    // ── Unknown / Missing MessageType ─────────────────────────────────────────

    @Test
    void onMessage_unknownMessageType_deadLettersAndPublishesAgentError() {
        givenMessageType("UNKNOWN_TYPE");
        givenBody("{}");

        listener.onMessage(context);

        verify(context).deadLetter(any(DeadLetterOptions.class));
        ArgumentCaptor<AgentErrorMessage> errorCaptor = ArgumentCaptor.forClass(AgentErrorMessage.class);
        verify(sender).sendAgentError(errorCaptor.capture());
        assertThat(errorCaptor.getValue().getErrorCode()).isEqualTo("UNKNOWN_MESSAGE_TYPE");
        assertThat(errorCaptor.getValue().getOriginalMessageType()).isEqualTo("UNKNOWN_TYPE");
    }

    @Test
    void onMessage_missingMessageType_deadLettersAndPublishesAgentError() {
        when(message.getApplicationProperties()).thenReturn(Map.of());
        givenBody("{}");

        listener.onMessage(context);

        verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(sender).sendAgentError(any(AgentErrorMessage.class));
    }

    // ── Error handling ────────────────────────────────────────────────────────

    @Test
    void onMessage_processorThrowsRuntimeException_deadLettersMessage() {
        givenMessageType("CERT_ISSUANCE");
        givenBody(certIssuanceJson());
        doThrow(new RuntimeException("Unexpected crash"))
                .when(issuanceProcessor).process(any(), any());

        listener.onMessage(context);

        verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(sender).sendAgentError(any(AgentErrorMessage.class));
    }

    @Test
    void onMessage_mdcIsAlwaysClearedAfterProcessing() {
        givenMessageType("CERT_ISSUANCE");
        givenBody(certIssuanceJson());
        org.slf4j.MDC.put("organizationId", "stale-value");

        listener.onMessage(context);

        assertThat(org.slf4j.MDC.get("organizationId")).isNull();
        assertThat(org.slf4j.MDC.get("requestId")).isNull();
    }

    @Test
    void onMessage_mdcClearedEvenOnException() {
        givenMessageType("CERT_ISSUANCE");
        givenBody(certIssuanceJson());
        doThrow(new RuntimeException("crash")).when(issuanceProcessor).process(any(), any());

        listener.onMessage(context);

        assertThat(org.slf4j.MDC.get("organizationId")).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void givenMessageType(String type) {
        when(message.getApplicationProperties()).thenReturn(Map.of("MessageType", type));
    }

    private void givenMessageTypeWithRetryCount(String type, int retryCount) {
        when(message.getApplicationProperties())
                .thenReturn(Map.of("MessageType", type, "RetryCount", retryCount));
    }

    private void givenBody(String json) {
        when(message.getBody()).thenReturn(MessageBody.fromString(json));
    }

    private String certIssuanceJson() {
        return """
                {
                  "requestId": "req-1",
                  "correlationId": "corr-1",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "wildcard": false,
                  "san": false,
                  "sanDomains": [],
                  "caProvider": "LETS_ENCRYPT",
                  "dnsProvider": "cloudflare",
                  "dnsCredentialHandle": "https://kv.vault.azure.net/secrets/cf-token"
                }
                """;
    }

    private String certRenewalJson() {
        return """
                {
                  "requestId": "req-2",
                  "correlationId": "corr-2",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "caProvider": "LETS_ENCRYPT",
                  "dnsProvider": "cloudflare",
                  "dnsCredentialHandle": "https://kv.vault.azure.net/secrets/cf-token",
                  "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1"
                }
                """;
    }

    private String certDeploymentJson() {
        return """
                {
                  "requestId": "req-3",
                  "correlationId": "corr-3",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1",
                  "targetType": "AZURE_KV",
                  "certificateName": "prod-app-tls",
                  "deploymentCredentialPath": "https://kv.vault.azure.net/secrets/azure-spn"
                }
                """;
    }

    private String certManualTxtRequestJson() {
        return """
                {
                  "requestId": "req-m1",
                  "correlationId": "corr-m1",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "wildcard": false,
                  "san": false,
                  "caProvider": "LETS_ENCRYPT",
                  "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1"
                }
                """;
    }

    private String certManualValidateJson() {
        return """
                {
                  "requestId": "req-m2",
                  "correlationId": "corr-m2",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "wildcard": false,
                  "san": false,
                  "caProvider": "LETS_ENCRYPT",
                  "acmeAccountHandle": "https://kv.vault.azure.net/secrets/acme-account",
                  "acmeOrderUrl": "https://acme.example.com/order/1",
                  "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1"
                }
                """;
    }

        private String certRevocationJson() {
                return """
                                {
                                    "requestId": "req-r1",
                                    "correlationId": "corr-r1",
                                    "organizationId": "organization-1",
                                    "certificateXref": "xref-1",
                                    "domain": "example.com",
                                    "caProvider": "LETS_ENCRYPT",
                                    "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1",
                                    "revocationReason": "KEY_COMPROMISE",
                                    "requestedAt": "2026-01-01T00:00:00Z",
                                    "userId": 123
                                }
                                """;
        }

    private String certKvSecretDeleteJson() {
        return """
                {
                  "requestId": "req-kvd1",
                  "correlationId": "corr-kvd1",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1",
                  "reason": "CERT_EXPIRED"
                }
                """;
    }
    private String deepHealthCheckJson() {
        return """
                {
                  "deepCheckId": "dhc-1",
                  "requestId": "req-dhc-1",
                  "correlationId": "corr-dhc-1",
                  "organizationId": "organization-1",
                  "chunkIndex": 0,
                  "totalChunks": 1,
                  "secretHandles": ["https://kv.vault.azure.net/secrets/example"]
                }
                """;
    }

    private String certKvDeleteJson() {
        return """
                {
                  "requestId": "req-kv1",
                  "correlationId": "corr-kv1",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "certSecretHandle": "https://kv.vault.azure.net/secrets/cert-xref-1",
                  "requestedAt": "2026-05-01T00:00:00Z"
                }
                """;
    }

    private String deviceIdentitySyncJson() {
        return """
                {
                  "requestId": "request-1",
                  "correlationId": "correlation-1",
                  "organizationId": "organization-1",
                  "sourceXref": "source-1",
                  "provider": "INTUNE",
                  "connectionProfileRef": "intune-primary",
                  "syncXref": "sync-1",
                  "mode": "FULL"
                }
                """;
    }
}
