// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.model.message.CertOwnSecretDeleteMessage;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Handles {@code CERT_OWN_SECRET_DELETE} from the server (e.g. expiry job).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertOwnSecretDeleteProcessor {

    private final SecretStore secretStore;
    private final AttemptRecords attemptRecords;

    public void process(CertOwnSecretDeleteMessage msg, InboundContext ctx) {
        log.info("[CertOwnSecretDeleteProcessor] cert={}, reason={}",
                msg.getCertificateXref(), msg.getReason());
        String path = msg.getCertSecretHandle();
        if (path != null && !path.isBlank() && secretStore.isOwnedByThisAgent(path)) {
            try { secretStore.delete(path); } catch (Exception ignored) { }
        }
        attemptRecords.delete(msg.getCertificateXref());
        ctx.complete();
    }
}
