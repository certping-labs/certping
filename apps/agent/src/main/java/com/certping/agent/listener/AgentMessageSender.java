// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.MessageSender;
import com.certping.agent.transport.TransportMessage;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.message.AgentErrorMessage;
import com.certping.agent.model.message.AgentDeepHealthCheckResponse;
import com.certping.agent.model.message.CaHealthReport;
import com.certping.agent.model.message.AgentHealthHeartbeat;
import com.certping.agent.model.message.CertDeploymentResponse;
import com.certping.agent.model.message.CertDiscoveryCompleteMessage;
import com.certping.agent.model.message.DeviceIdentitySyncCompleteMessage;
import com.certping.agent.model.message.DeviceIdentitySyncResponse;
import com.certping.agent.model.message.IotDeviceSyncResponse;
import com.certping.agent.model.message.IotCertificateRevocationResponse;
import com.certping.agent.model.message.IotIntuneRevocationPollResponse;
import com.certping.agent.model.message.IotIntuneRevocationUploadResponse;
import com.certping.agent.model.message.DeviceSourceHealthMessage;
import com.certping.agent.model.message.CertDiscoveryResponse;
import com.certping.agent.model.message.CertIssuanceResponse;
import com.certping.agent.model.message.CertSecretDeleteResponse;
import com.certping.agent.model.message.CertManualTxtResponse;
import com.certping.agent.model.message.CertRevocationResponse;
import com.certping.agent.model.message.ScepCertIssuedResponse;
import com.certping.agent.model.message.ScepCertRequestedResponse;
import com.certping.agent.model.message.ScepCertResultResponse;
import com.certping.agent.model.message.CertificateProfileResponse;
import com.certping.agent.model.message.CertificateProfileSyncCompleteMessage;
import com.certping.agent.model.message.CertificateProfileSyncResponse;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

@Slf4j
@Component
@Lazy
public class AgentMessageSender {
    /** Per-page sync traffic: one line each would bury the per-sync summaries. */
    private static final java.util.Set<String> CHATTY_MESSAGE_TYPES = java.util.Set.of(
            "DEVICE_IDENTITY_SYNC_RESPONSE_PART", "IOT_CERTIFICATE_PROFILE_SYNC_RESPONSE_PART");


    private final MessageSender outboundSenderClient;
    private final ObjectMapper  objectMapper;

    public AgentMessageSender(
            @Qualifier("outboundSender") MessageSender outboundSenderClient,
            ObjectMapper objectMapper) {
        this.outboundSenderClient = outboundSenderClient;
        this.objectMapper         = objectMapper;
    }

    public void sendIssuanceResponse(CertIssuanceResponse response) {
        send(response, "CERT_ISSUANCE_RESPONSE");
    }

    public void sendManualTxtResponse(CertManualTxtResponse response) {
        send(response, "CERT_MANUAL_TXT_RESPONSE");
    }

    public void sendDeploymentResponse(CertDeploymentResponse response) {
        send(response, "CERT_DEPLOYMENT_RESPONSE");
    }

    public void sendRevocationResponse(CertRevocationResponse response) {
        send(response, "CERT_REVOCATION_RESPONSE");
    }

    public void sendKvDeleteResponse(CertSecretDeleteResponse response) {
        send(response, "CERT_SECRET_DELETE_RESPONSE");
    }

    public void sendAgentError(AgentErrorMessage error) {
        send(error, "AGENT_ERROR");
    }

    public void sendHealthHeartbeat(AgentHealthHeartbeat heartbeat) {
        send(heartbeat, "AGENT_HEALTH_HEARTBEAT");
    }

    public void sendDeepHealthCheckResponse(AgentDeepHealthCheckResponse response) {
        send(response, "AGENT_DEEP_HEALTH_CHECK_RESPONSE");
    }

    public void sendCaHealthReport(CaHealthReport report) {
        send(report, "AGENT_CA_HEALTH_REPORT");
    }

    public void sendScepCertRequested(ScepCertRequestedResponse response) {
        send(response, "SCEP_CERT_REQUESTED");
    }

    public void sendScepCertIssued(ScepCertIssuedResponse response) {
        send(response, "SCEP_CERT_ISSUED");
    }

    public void sendScepCertResult(ScepCertResultResponse response) {
        send(response, "SCEP_CERT_RESULT");
    }

    public void sendDiscoveryResponse(CertDiscoveryResponse response) {
        send(response, "CERT_DISCOVERY_RESPONSE");
    }

    public void sendIotDeviceSyncResponse(IotDeviceSyncResponse response) {
        send(response, "IOT_DEVICE_SYNC_RESPONSE");
    }

    public void sendIotCertificateRevocationResponse(IotCertificateRevocationResponse response) {
        send(response, "IOT_CERTIFICATE_REVOCATION_RESULT");
    }

    public void sendIotIntuneRevocationPollResponse(IotIntuneRevocationPollResponse response) {
        send(response, "IOT_INTUNE_REVOCATION_POLL_RESULT");
    }

    public void sendIotIntuneRevocationUploadResponse(IotIntuneRevocationUploadResponse response) {
        send(response, "IOT_INTUNE_REVOCATION_UPLOAD_RESULT");
    }

    public void sendDeviceIdentitySyncResponse(DeviceIdentitySyncResponse response) {
        send(response, "DEVICE_IDENTITY_SYNC_RESPONSE_PART");
    }

    public void sendDeviceIdentitySyncComplete(DeviceIdentitySyncCompleteMessage message) {
        send(message, "DEVICE_IDENTITY_SYNC_RESPONSE_COMPLETE");
    }

    public void sendDeviceSourceHealth(DeviceSourceHealthMessage message) {
        send(message, "IOT_DEVICE_SOURCE_HEALTH");
    }

    public void sendCertificateProfileResponse(CertificateProfileResponse response) {
        send(response, "IOT_CERTIFICATE_PROFILE_RESPONSE");
    }

    public void sendCertificateProfileSyncResponse(CertificateProfileSyncResponse response) {
        send(response, "IOT_CERTIFICATE_PROFILE_SYNC_RESPONSE_PART");
    }

    public void sendCertificateProfileSyncComplete(CertificateProfileSyncCompleteMessage response) {
        send(response, "IOT_CERTIFICATE_PROFILE_SYNC_RESPONSE_COMPLETE");
    }

    public void sendDiscoveryComplete(CertDiscoveryCompleteMessage message) {
        send(message, "CERT_DISCOVERY_COMPLETE");
    }

    private void send(Object payload, String messageType) {
        try {
            // The agent token authenticates every message, and the server stamps the organization
            // from that token itself, so nothing here claims an organization.
            byte[] body = objectMapper.writeValueAsBytes(payload);
            TransportMessage message = new TransportMessage(body);
            message.getApplicationProperties().put("MessageType", messageType);

            outboundSenderClient.sendMessage(message);
            // Sync response batches are per-page and a large organization sends a thousand of them,
            // which would drown the one-per-sync lines the processors deliberately keep at INFO.
            // Every other message type stays at INFO: issuance and revocation flows depend on it.
            if (CHATTY_MESSAGE_TYPES.contains(messageType)) {
                log.debug("Sent {} to queue={}", messageType, outboundSenderClient.getEntityPath());
            } else {
                log.info("Sent {} to queue={}", messageType, outboundSenderClient.getEntityPath());
            }
        } catch (JacksonException e) {
            // Serialization bugs are permanent — retrying can never recover.
            // Using TransientAgentException here caused redelivery up to max-delivery-count
            // on a defect that requires a code fix, not a transient network retry.
            throw new PermanentAgentException("SERIALIZATION_FAILED",
                    "Failed to serialize " + messageType + ": " + e.getMessage(), e);
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new TransientAgentException("SEND_FAILED",
                    "Failed to send " + messageType + " to the server: " + e.getMessage(), e);
        }
    }
}
