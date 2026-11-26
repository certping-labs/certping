// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertRevocationMessage;
import com.certping.agent.model.message.CertRevocationResponse;
import com.certping.agent.ssl.SslRevocationService;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Handles CERT_REVOCATION_COMMAND from the server.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertRevocationProcessor {

    private final SecretStore          secretStore;
    private final SslRevocationService revocationService;
    private final AgentMessageSender   sender;

    public void process(CertRevocationMessage msg, InboundContext ctx) {
        log.info("[CertRevocationProcessor] Starting revocation: cert={}, ca={}, reason={}",
                msg.getCertificateXref(), msg.getCaProvider(), msg.getRevocationReason());

        String bundle = null;
        if (msg.getCaProvider() == CaProvider.LETS_ENCRYPT) {
            bundle = secretStore.read(msg.getCertSecretHandle());
            if (bundle == null || bundle.isBlank()) {
                throw new PermanentAgentException("KV_SECRET_NOT_FOUND",
                        "No cert bundle found at KV path: " + msg.getCertSecretHandle()
                                + ". The certificate may have been deleted from the agent Key Vault.");
            }
        }

        String caCredentialRaw = null;
        if (msg.getCaProvider() == CaProvider.DIGICERT) {
            if (msg.getCaCredentialHandle() == null || msg.getCaCredentialHandle().isBlank()) {
                throw new PermanentAgentException("MISSING_CA_CREDENTIAL",
                        "caCredentialHandle is required for DigiCert revocation (KV URI for API key)");
            }
            caCredentialRaw = secretStore.read(msg.getCaCredentialHandle());
            if (caCredentialRaw == null || caCredentialRaw.isBlank()) {
                throw new PermanentAgentException("KV_SECRET_NOT_FOUND",
                        "No CA credential found at KV path: " + msg.getCaCredentialHandle());
            }
        }

        revocationService.revoke(
                msg.getCaProvider(), bundle, msg.getOrderId(), msg.getRevocationReason(), caCredentialRaw);

        String certPath = msg.getCertSecretHandle();
        if (certPath != null && !certPath.isBlank() && secretStore.isOwnedByThisAgent(certPath)) {
            try { secretStore.delete(certPath); } catch (Exception ignored) { }
        }

        CertRevocationResponse response = CertRevocationResponse.builder()
                .requestId(msg.getRequestId())
                .correlationId(msg.getCorrelationId())
                .organizationId(msg.getOrganizationId())
                .certificateXref(msg.getCertificateXref())
                .caProvider(msg.getCaProvider())
                .revocationReason(msg.getRevocationReason())
                .revokedAt(Instant.now().toString())
                .build();

        sender.sendRevocationResponse(response);
        ctx.complete();

        log.info("[CertRevocationProcessor] Revocation complete: cert={}, ca={}",
                msg.getCertificateXref(), msg.getCaProvider());
    }
}
