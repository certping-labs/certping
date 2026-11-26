// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.startup;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/** Probes the secret store on startup by reading a non-existent handle — NOT_FOUND means auth+reachability OK. */
@Slf4j
@Component
@RequiredArgsConstructor
public class SecretStoreStartupValidator {

    private static final String PROBE_NAME = "startup-probe";

    private final SecretStore secretStore;

    @EventListener(ApplicationReadyEvent.class)
    public void validateAccess() {
        String probeHandle;
        try {
            probeHandle = secretStore.handleFor(PROBE_NAME);
        } catch (Exception e) {
            log.warn("[SECRET-STORE-STARTUP] secret store not configured — {} — " +
                     "credential reads will fail at runtime", e.getMessage());
            return;
        }

        try {
            secretStore.read(probeHandle);
            log.info("[SECRET-STORE-STARTUP] {} reachable — auth OK", secretStore.provider());

        } catch (PermanentAgentException e) {
            String code = e.getErrorCode() == null ? "" : e.getErrorCode();
            if (code.endsWith("_SECRET_NOT_FOUND")) {
                log.info("[SECRET-STORE-STARTUP] {} reachable — auth OK", secretStore.provider());
            } else if (code.endsWith("_ACCESS_DENIED")) {
                log.warn("[SECRET-STORE-STARTUP] {} reachable but identity lacks read permission — " +
                         "grant read/get on the store to the agent's identity. Credential reads will fail at runtime.",
                        secretStore.provider());
            } else {
                log.warn("[SECRET-STORE-STARTUP] {} check failed: [{}] {} — credential reads may fail at runtime",
                        secretStore.provider(), code, e.getMessage());
            }
        } catch (Exception e) {
            log.warn("[SECRET-STORE-STARTUP] {} unreachable: {} — " +
                     "credential reads will fail at runtime. Check store configuration and network connectivity.",
                    secretStore.provider(), e.getMessage());
        }
    }
}
