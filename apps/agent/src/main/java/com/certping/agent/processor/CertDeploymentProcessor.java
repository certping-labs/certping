// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.DeploymentService;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.model.message.CertDeploymentResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Handles CERT_DEPLOYMENT commands from this organization's inbound queue.
 *
 * <p>The processor delegates deployment to {@link DeploymentService}, publishes the resulting
 * {@code CERT_DEPLOYMENT_RESPONSE}, and only completes the inbound message after the response
 * has been sent. That ordering prevents the server from observing a successful deployment result that the
 * agent failed to publish.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertDeploymentProcessor {

    private final DeploymentService  deploymentService;
    private final AgentMessageSender sender;

    public void process(CertDeploymentMessage message, InboundContext context) {
        // requestedAt shows dispatch-to-processing latency in structured logs
        log.info("Processing CERT_DEPLOYMENT — targetType={}, certSecretHandle={}, requestedAt={}",
                message.getTargetType(),
                message.getCertSecretHandle(), message.getRequestedAt());

        try {
            DeploymentResult result = deploymentService.deploy(message);

            // A success response without a target identifier would leave the server with an unverifiable deployment result,
            // so we fail the message before acknowledging it.
            if (result.targetResourceId() == null || result.targetResourceId().isBlank()) {
                throw new PermanentAgentException("DEPLOY_RESULT_NULL_RESOURCE_ID",
                        "Deployment adapter returned null/empty targetResourceId for xref=" +
                        message.getCertificateXref() + " targetType=" + message.getTargetType() +
                        " — deployment may have partially succeeded but result is unverifiable.");
            }

            CertDeploymentResponse response = CertDeploymentResponse.builder()
                    .requestId(message.getRequestId())
                    .correlationId(message.getCorrelationId())
                    .organizationId(message.getOrganizationId())
                    .certificateXref(message.getCertificateXref())
                    .targetType(message.getTargetType())
                    .status("SUCCESS")
                    .targetResourceId(result.targetResourceId())
                    .configJson(result.configJson())
                    .respondedAt(OffsetDateTime.now(ZoneOffset.UTC).toString())
                    .build();

            sender.sendDeploymentResponse(response);
            context.complete();
            log.info("CERT_DEPLOYMENT_RESPONSE sent: xref={}, targetResourceId={}",
                    message.getCertificateXref(), result.targetResourceId());

        } catch (Exception e) {
            log.error("CERT_DEPLOYMENT failed: xref={}, error={}", message.getCertificateXref(), e.getMessage(), e);
            throw e instanceof RuntimeException re ? re
                    : new PermanentAgentException("DEPLOYMENT_FAILED", e.getMessage(), e);
        }
    }
}
