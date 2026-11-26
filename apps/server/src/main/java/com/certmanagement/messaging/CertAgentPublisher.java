// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.InboundSenders;
import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.messaging.transport.TransportProperties;
import com.certmanagement.dto.cert.IssueManualRequest;
import com.certmanagement.entity.CertManualIssuanceStateEntity;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.iot.messaging.DeviceIdentitySyncCommand;
import com.certmanagement.iot.messaging.IotDeviceSyncCommand;
import com.certmanagement.iot.revocation.IotCertificateRevocationCommand;
import com.certmanagement.iot.revocation.IotIntuneRevocationPollCommand;
import com.certmanagement.iot.revocation.IotIntuneRevocationUploadCommand;
import com.certmanagement.iot.profile.CertificateProfileCommand;
import com.certmanagement.iot.profile.CertificateProfileSyncCommand;
import com.certmanagement.messaging.model.CertDiscoveryCommand;
import com.certmanagement.messaging.model.CertSecretDeleteCommand;
import com.certmanagement.messaging.model.CertDeploymentCommand;
import com.certmanagement.messaging.model.CertIssuanceCommand;
import com.certmanagement.messaging.model.CertManualTxtRequestCommand;
import com.certmanagement.messaging.model.CertManualValidateCommand;
import com.certmanagement.messaging.model.CertRenewalCommand;
import com.certmanagement.messaging.model.CertOwnSecretDeleteCommand;
import com.certmanagement.messaging.model.CertRevocationCommand;
import com.certmanagement.util.MdcIds;
import com.certmanagement.util.OtelSpanContext;
import com.certmanagement.messaging.model.AgentDeepHealthCheckCommand;
import com.certmanagement.messaging.model.AgentHeartbeatCadenceUpdateCommand;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Publishes certificate lifecycle commands to the appropriate inbound queue.
 *
 * <h2>Queue routing</h2>
 * Every command goes to its organization's own inbound queue {@code {orgId}-agent-inbound}
 * (no DB, no security context, no shared cache).
 *
 * <p>The sender itself is resolved through {@link InboundSenders} keyed by the queue name.
 *
 * <p>Each message still carries the application properties
 * ({@code MessageType}, {@code organizationId}, {@code requestId}) for log/MDC correlation,
 * but they are not load-bearing for routing.
 */
@Slf4j
@Component
public class CertAgentPublisher {

    /**
     * Queue time to live of a {@code CERT_RENEWAL}, equal to the agent's renewal attempt-age bound
     * ({@code agent.retry.max-attempt-age-renewal}): an agent that was offline never runs a renewal that
     * the server has since given up on and sent again.
     */
    public static final Duration RENEWAL_TIME_TO_LIVE = Duration.ofHours(168);

    private final InboundSenders senderFactory;
    private final TransportProperties      transportProperties;
    private final ObjectMapper             objectMapper;

    private final AgentTargets             agentTargets;

    public CertAgentPublisher(InboundSenders senderFactory,
                              TransportProperties transportProperties,
                              ObjectMapper objectMapper) {
        this(senderFactory, transportProperties, objectMapper, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public CertAgentPublisher(InboundSenders senderFactory,
                              TransportProperties transportProperties,
                              ObjectMapper objectMapper,
                              AgentTargets agentTargets) {
        this.senderFactory = senderFactory;
        this.transportProperties = transportProperties;
        this.objectMapper  = objectMapper;
        this.agentTargets  = agentTargets;
    }

    private Long sourceAgent(String organizationId, String sourceXref) {
        return agentTargets == null || organizationId == null ? null
                : agentTargets.forSource(organizationId, sourceXref);
    }

    public void publishIssuance(CertIssuanceCommand command) {
        String messageId = sendToInbound(command, "CERT_ISSUANCE",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId());
        log.info("Published command: messageType=CERT_ISSUANCE, queue={}, organizationId={}, xref={}, messageId={}",
                queueFor(command.getOrganizationId(), command.getOrgType()),
                command.getOrganizationId(), command.getCertificateXref(), messageId);
    }

    public void publishRenewal(CertRenewalCommand command) {
        String messageId = sendToInbound(command, "CERT_RENEWAL",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(), null,
                RENEWAL_TIME_TO_LIVE);
        log.info("Published command: messageType=CERT_RENEWAL, queue={}, organizationId={}, xref={}, messageId={}",
                queueFor(command.getOrganizationId(), command.getOrgType()),
                command.getOrganizationId(), command.getCertificateXref(), messageId);
    }

    public void publishDeployment(CertDeploymentCommand command) {
        String messageId = sendToInbound(command, "CERT_DEPLOYMENT",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId());
        log.info("Published command: messageType=CERT_DEPLOYMENT, queue={}, organizationId={}, xref={}, messageId={}",
                queueFor(command.getOrganizationId(), command.getOrgType()),
                command.getOrganizationId(), command.getCertificateXref(), messageId);
    }

    public void publishRevocationCommand(CertRevocationCommand command) {
        String messageId = sendToInbound(command, "CERT_REVOCATION_COMMAND",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId());
        log.info("Published command: messageType=CERT_REVOCATION_COMMAND, queue={}, organizationId={}, xref={}, messageId={}",
                queueFor(command.getOrganizationId(), command.getOrgType()),
                command.getOrganizationId(), command.getCertificateXref(), messageId);
    }

    /**
     * Asks the agent to soft-delete the cert PEM secret in the agent Key Vault (e.g. after EXPIRED marking).
     */
    public void publishKvSecretDeleteCommand(CertOwnSecretDeleteCommand command) {
        String messageId = sendToInbound(command, "CERT_OWN_SECRET_DELETE",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId());
        log.info("Published command: messageType=CERT_OWN_SECRET_DELETE, queue={}, organizationId={}, xref={}, reason={}, messageId={}",
                queueFor(command.getOrganizationId(), command.getOrgType()),
                command.getOrganizationId(), command.getCertificateXref(), command.getReason(), messageId);
    }

    public void publishHeartbeatCadenceUpdate(String organizationId, String orgType, int heartbeatCadenceMinutes) {
        AgentHeartbeatCadenceUpdateCommand command = AgentHeartbeatCadenceUpdateCommand.builder()
                .organizationId(organizationId)
                .orgType(orgType)
                .requestId(MdcIds.requestId())
                .correlationId(MdcIds.correlationId())
                .heartbeatCadenceMinutes(heartbeatCadenceMinutes)
                .build();
        String messageId = sendToInbound(command, "AGENT_HEARTBEAT_CADENCE_UPDATE",
                organizationId, orgType, command.getRequestId());
        log.info("Published command: messageType=AGENT_HEARTBEAT_CADENCE_UPDATE, queue={}, organizationId={}, heartbeatCadenceMinutes={}, messageId={}",
                queueFor(organizationId, orgType), organizationId, heartbeatCadenceMinutes, messageId);
    }

    public void publishDeepHealthCheck(AgentDeepHealthCheckCommand command) {
        String messageId = sendToInbound(command, "AGENT_DEEP_HEALTH_CHECK",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId());
        log.info("Published command: messageType=AGENT_DEEP_HEALTH_CHECK, queue={}, organizationId={}, deepCheckId={}, chunk={}/{}, messageId={}",
                queueFor(command.getOrganizationId(), command.getOrgType()),
                command.getOrganizationId(),
                command.getDeepCheckId(),
                command.getChunkIndex(),
                command.getTotalChunks(),
                messageId);
    }

    // ------------------------------------------------------------------ //
    //  Manual issuance flow
    // ------------------------------------------------------------------ //

    public void publishManualTxtRequest(CertificateEntity cert,
                                        String orgType,
                                        List<IssueManualRequest.SanDomainEntry> sanEntries) {
        publishManualTxtRequest(cert, orgType, sanEntries,
                MdcIds.requestId(),
                MdcIds.correlationId());
    }

    public void publishManualTxtRequest(CertificateEntity cert,
                                        String orgType,
                                        List<IssueManualRequest.SanDomainEntry> sanEntries,
                                        String requestId,
                                        String correlationId) {
        List<CertManualTxtRequestCommand.SanDomainEntry> cmdSanEntries = sanEntries == null
                ? List.of()
                : sanEntries.stream()
                        .map(e -> CertManualTxtRequestCommand.SanDomainEntry.builder()
                                .patterns(e.getPatterns())
                                .build())
                        .toList();

        CertManualTxtRequestCommand command = CertManualTxtRequestCommand.builder()
                .organizationId(cert.getOrganizationId().toString())
                .orgType(orgType)
                .requestId(requestId)
                .correlationId(correlationId)
                .certificateXref(cert.getCertificateXref())
                .domain(cert.getDomain())
                .wildcard(Boolean.TRUE.equals(cert.getWildcard()))
                .san(Boolean.TRUE.equals(cert.getSan()))
                .caProvider(CaProvider.LETS_ENCRYPT)
                .acmeAccountHandle(cert.getAcmeAccountHandle())
                .certSecretHandle(cert.getCertSecretHandle())
                .sanDomainEntries(cmdSanEntries.isEmpty() ? null : cmdSanEntries)
                .build();

        String messageId = sendToInbound(command, "CERT_MANUAL_TXT_REQUEST",
                cert.getOrganizationId().toString(), orgType, requestId);
        log.info("Published command: messageType=CERT_MANUAL_TXT_REQUEST, queue={}, organizationId={}, xref={}, messageId={}",
                queueFor(cert.getOrganizationId().toString(), orgType),
                cert.getOrganizationId(), cert.getCertificateXref(), messageId);
    }

    public void publishManualDnsValidate(CertificateEntity cert,
                                         String orgType,
                                         CertManualIssuanceStateEntity state) {
        publishManualDnsValidate(cert, orgType, state,
                MdcIds.requestId(),
                MdcIds.correlationId());
    }

    public void publishManualDnsValidate(CertificateEntity cert,
                                         String orgType,
                                         CertManualIssuanceStateEntity state,
                                         String requestId,
                                         String correlationId) {
        List<CertManualValidateCommand.TxtRecord> txtRecords;
        List<CertManualValidateCommand.SanDomainEntry> cmdSanEntries =
                cert.getSanDomains() == null || cert.getSanDomains().length == 0
                        ? List.of()
                        : List.of(CertManualValidateCommand.SanDomainEntry.builder()
                                .patterns(List.of(cert.getSanDomains()))
                                .build());
        try {
            List<Map<String, String>> raw = objectMapper.readValue(
                    state.getTxtRecords(), new TypeReference<>() {});
            txtRecords = raw.stream()
                    .map(r -> CertManualValidateCommand.TxtRecord.builder()
                            .recordName(r.get("recordName"))
                            .recordValue(r.get("recordValue"))
                            .domain(r.get("domain"))
                            .build())
                    .toList();
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to deserialize txtRecords from manual issuance state for xref="
                    + cert.getCertificateXref(), e);
        }

        CertManualValidateCommand command = CertManualValidateCommand.builder()
                .organizationId(cert.getOrganizationId().toString())
                .orgType(orgType)
                .requestId(requestId)
                .correlationId(correlationId)
                .certificateXref(cert.getCertificateXref())
                .domain(cert.getDomain())
                .wildcard(Boolean.TRUE.equals(cert.getWildcard()))
                .san(Boolean.TRUE.equals(cert.getSan()))
                .caProvider(CaProvider.LETS_ENCRYPT)
                .acmeAccountHandle(state.getAcmeAccountHandle())
                .acmeOrderUrl(state.getAcmeOrderUrl())
                .certSecretHandle(cert.getCertSecretHandle())
                .sanDomainEntries(cmdSanEntries.isEmpty() ? null : cmdSanEntries)
                .txtRecords(txtRecords)
                .build();

        String messageId = sendToInbound(command, "CERT_MANUAL_DNS_VALIDATE",
                cert.getOrganizationId().toString(), orgType, requestId);
        log.info("Published command: messageType=CERT_MANUAL_DNS_VALIDATE, queue={}, organizationId={}, xref={}, messageId={}",
                queueFor(cert.getOrganizationId().toString(), orgType),
                cert.getOrganizationId(), cert.getCertificateXref(), messageId);
    }

    /**
     * Publishes a discovery command with {@link TransportProperties#getDiscoveryCommandTtl()} as
     * its time-to-live, so a scan nobody picked up expires rather than running late.
     */
    public void publishDiscoveryCommand(CertDiscoveryCommand command) {
        sendToInbound(command, "CERT_DISCOVERY",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(), null,
                transportProperties.getDiscoveryCommandTtl());
        log.info("Published CERT_DISCOVERY: organizationId={}, targetType={}, requestId={}",
                command.getOrganizationId(), command.getTargetType(), command.getRequestId());
    }

    public void publishDeviceIdentitySyncCommand(DeviceIdentitySyncCommand command) {
        sendToInbound(command, "DEVICE_IDENTITY_SYNC_COMMAND",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(),
                command.getSyncXref(), null, sourceAgent(command.getOrganizationId(), command.getSourceXref()));
        log.info("Published DEVICE_IDENTITY_SYNC_COMMAND: organizationId={}, sourceXref={}, syncXref={}, requestId={}",
                command.getOrganizationId(), command.getSourceXref(), command.getSyncXref(),
                command.getRequestId());
    }

    public void publishDeviceSync(IotDeviceSyncCommand command) {
        sendToInbound(command, "IOT_DEVICE_SYNC_COMMAND",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(),
                command.getRequestId(), null, sourceAgent(command.getOrganizationId(), command.getSourceXref()));
        log.info("Published IOT_DEVICE_SYNC_COMMAND: organizationId={}, sourceXref={}, deviceXref={}, "
                        + "certificateCount={}, managedDeviceId={}, reason={}, requestId={}",
                command.getOrganizationId(), command.getSourceXref(), command.getDeviceXref(),
                command.getCertificateXrefs().size(), command.getManagedDeviceId(), command.getReason(),
                command.getRequestId());
    }

    public void publishIotCertificateRevocation(IotCertificateRevocationCommand command) {
        sendToInbound(command, "IOT_CERTIFICATE_REVOCATION_COMMAND",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(),
                command.getRequestId(), null,
                agentTargets == null || command.getOrganizationId() == null ? null
                        : agentTargets.forCertificate(command.getOrganizationId(), command.getCertificateXref()));
        log.info("Published IOT_CERTIFICATE_REVOCATION_COMMAND: organizationId={}, "
                        + "certificateXref={}, operationXref={}, attemptRequestId={}",
                command.getOrganizationId(), command.getCertificateXref(),
                command.getOperationXref(), command.getRequestId());
    }

    public void publishIotIntuneRevocationPoll(IotIntuneRevocationPollCommand command) {
        sendToInbound(command, "IOT_INTUNE_REVOCATION_POLL_COMMAND",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(),
                command.getRequestId(), null, sourceAgent(command.getOrganizationId(), command.getSourceXref()));
        log.info("Published IOT_INTUNE_REVOCATION_POLL_COMMAND: organizationId={}, sourceXref={}, transactionId={}",
                command.getOrganizationId(), command.getSourceXref(), command.getTransactionId());
    }

    public void publishIotIntuneRevocationUpload(IotIntuneRevocationUploadCommand command) {
        sendToInbound(command, "IOT_INTUNE_REVOCATION_UPLOAD_COMMAND",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(),
                command.getRequestId(), null, sourceAgent(command.getOrganizationId(), command.getSourceXref()));
        log.info("Published IOT_INTUNE_REVOCATION_UPLOAD_COMMAND: organizationId={}, sourceXref={}, transactionId={}, count={}",
                command.getOrganizationId(), command.getSourceXref(), command.getTransactionId(),
                command.getResults().size());
    }

    public void publishCertificateProfileCommand(CertificateProfileCommand command) {
        sendToInbound(command, "IOT_CERTIFICATE_PROFILE_COMMAND",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(),
                command.getOperationXref(), null, sourceAgent(command.getOrganizationId(), command.getSourceXref()));
        log.info("Published IOT_CERTIFICATE_PROFILE_COMMAND: organizationId={}, sourceXref={}, profileXref={}, operation={}",
                command.getOrganizationId(), command.getSourceXref(), command.getProfileXref(),
                command.getOperation());
    }

    public void publishCertificateProfileSyncCommand(CertificateProfileSyncCommand command) {
        sendToInbound(command, "IOT_CERTIFICATE_PROFILE_SYNC_COMMAND",
                command.getOrganizationId(), command.getOrgType(), command.getRequestId(),
                command.getRequestId(), null, sourceAgent(command.getOrganizationId(), command.getSourceXref()));
        log.info("Published IOT_CERTIFICATE_PROFILE_SYNC_COMMAND: organizationId={}, sourceXref={}, requestId={}",
                command.getOrganizationId(), command.getSourceXref(), command.getRequestId());
    }

    public void publishKvDeleteCommand(String certXref, String certSecretHandle,
                                       String organizationId, String orgType) {
        if (certXref == null || certXref.isBlank() || organizationId == null || organizationId.isBlank()) {
            log.warn("publishKvDeleteCommand: skipping — certXref or organizationId is blank (xref={}, orgId={})",
                    certXref, organizationId);
            return;
        }
        CertSecretDeleteCommand command = CertSecretDeleteCommand.builder()
                .requestId(MdcIds.requestId())
                .correlationId(MdcIds.correlationId())
                .organizationId(organizationId)
                .orgType(orgType)
                .certificateXref(certXref)
                .certSecretHandle(certSecretHandle)
                .requestedAt(java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).toString())
                .build();
        String messageId = sendToInbound(command, "CERT_SECRET_DELETE_COMMAND",
                organizationId, orgType, command.getRequestId());
        log.info("Published command: messageType=CERT_SECRET_DELETE_COMMAND, queue={}, organizationId={}, xref={}, messageId={}",
                queueFor(organizationId, orgType), organizationId, certXref, messageId);
    }

    /**
     * Send the payload to the appropriate inbound queue. Returns the message id set on the
     * message, which is {@code null} when the command carries no idempotency key.
     */
    private String sendToInbound(Object payload, String messageType,
                                 String organizationId, String orgType, String requestId) {
        return sendToInbound(payload, messageType, organizationId, orgType, requestId, null);
    }

    private String sendToInbound(Object payload,
                                 String messageType,
                                 String organizationId,
                                 String orgType,
                                 String requestId,
                                 String idempotencyKey) {
        return sendToInbound(payload, messageType, organizationId, orgType, requestId, idempotencyKey, null);
    }

    private String sendToInbound(Object payload, String messageType, String organizationId, String orgType,
                                 String requestId, String idempotencyKey, Duration timeToLive) {
        return sendToInbound(payload, messageType, organizationId, orgType, requestId, idempotencyKey, timeToLive,
                null);
    }

    /**
     * @param timeToLive queue-side expiry for the message, or {@code null} for none
     * @param targetAgentTokenId the only agent that may receive it, or {@code null} for any agent of the
     *                           organization
     */
    private String sendToInbound(Object payload,
                                 String messageType,
                                 String organizationId,
                                 String orgType,
                                 String requestId,
                                 String idempotencyKey,
                                 Duration timeToLive,
                                 Long targetAgentTokenId) {
        if (organizationId == null || organizationId.isBlank()) {
            throw new IllegalArgumentException(
                    "organizationId must be set on " + messageType + " — required for log/MDC correlation");
        }
        try {
            String body = objectMapper.writeValueAsString(payload);
            TransportMessage message = new TransportMessage(body);
            if (idempotencyKey != null && !idempotencyKey.isBlank()) {
                message.setMessageId(idempotencyKey);
            }
            if (timeToLive != null && !timeToLive.isNegative() && !timeToLive.isZero()) {
                message.setTimeToLive(timeToLive);
            }
            // Correlation only, except the target agent, which the gateway routes on.
            message.getApplicationProperties().put("MessageType",    messageType);
            message.getApplicationProperties().put("organizationId", organizationId);
            message.getApplicationProperties().put("requestId",      requestId);
            if (targetAgentTokenId != null) {
                message.getApplicationProperties().put(
                        com.certmanagement.messaging.transport.AgentGatewayHeaders.TARGET_AGENT_TOKEN_PROPERTY,
                        String.valueOf(targetAgentTokenId));
            }
            String queueName = queueFor(organizationId, orgType);
            MessageSender sender = senderFactory.senderFor(queueName);
            sender.sendMessage(message);
            MDC.put("organizationId", organizationId);
            OtelSpanContext.enrichAgentPublish(
                    requestId,
                    MdcIds.correlationId(),
                    organizationId,
                    certificateXrefFromBody(body),
                    messageType,
                    message.getMessageId());
            return message.getMessageId();
        } catch (JacksonException e) {
            throw new RuntimeException(
                    "Failed to serialize " + messageType + " command: " + e.getMessage(), e);
        }
    }

    private String certificateXrefFromBody(String body) {
        try {
            JsonNode json = objectMapper.readTree(body);
            String certificateXref = json.path("certificateXref").asString("");
            return certificateXref.isEmpty() ? null : certificateXref;
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Resolves the inbound queue name: every organization's commands go to its own inbound queue.
     * {@code orgType} is accepted for the callers' convenience and does not affect routing.
     *
     * <p>Package-private so the routing decision can be tested directly without exercising the
     * full send path.
     */
    String queueFor(String organizationId, String orgType) {
        return transportProperties.inboundQueueFor(organizationId);
    }
}
