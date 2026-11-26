// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.model.message.CertSecretDeleteMessage;
import com.certping.agent.model.message.CertSecretDeleteResponse;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class CertSecretDeleteProcessor {

    private final SecretStore          secretStore;
    private final AttemptRecords       attemptRecords;
    private final AgentMessageSender   sender;

    public void process(CertSecretDeleteMessage msg, InboundContext ctx) {
        log.info("[CertSecretDeleteProcessor] Deleting cert secret: xref={}, secretHandle={}",
                msg.getCertificateXref(), msg.getCertSecretHandle());

        String status    = "SUCCESS";
        String errorCode = null;
        String errorDetail = null;

        try {
            if (msg.getCertSecretHandle() == null || msg.getCertSecretHandle().isBlank()) {
                log.warn("[CertSecretDeleteProcessor] No certSecretHandle for xref={} — nothing to delete",
                        msg.getCertificateXref());
                status = "SKIPPED";
            } else {
                secretStore.delete(msg.getCertSecretHandle());
                log.info("[CertSecretDeleteProcessor] KV secret deleted: xref={}", msg.getCertificateXref());
                attemptRecords.delete(msg.getCertificateXref());
            }
        } catch (Exception e) {
            log.error("[CertSecretDeleteProcessor] Failed to delete KV secret xref={}: {}",
                    msg.getCertificateXref(), e.getMessage(), e);
            status     = "FAILED";
            errorCode  = "KV_DELETE_FAILED";
            errorDetail = e.getMessage();
        }

        CertSecretDeleteResponse response = CertSecretDeleteResponse.builder()
                .requestId(msg.getRequestId())
                .correlationId(msg.getCorrelationId())
                .organizationId(msg.getOrganizationId())
                .certificateXref(msg.getCertificateXref())
                .status(status)
                .errorCode(errorCode)
                .errorDetail(errorDetail)
                .respondedAt(Instant.now().toString())
                .build();

        sender.sendKvDeleteResponse(response);
        ctx.complete();

        log.info("[CertSecretDeleteProcessor] Completed xref={}, status={}", msg.getCertificateXref(), status);
    }
}
