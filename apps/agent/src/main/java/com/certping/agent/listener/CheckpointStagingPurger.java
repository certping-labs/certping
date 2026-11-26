// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Best-effort cleanup of the {@code Checkpoint.PrivateKeyKvPath} staging slot when a message
 * is about to be dead-lettered ({@code RETRY_GIVE_UP}). The slot will never be read
 * again — the issuance is dead — so deleting it here keeps the key from staying in
 * the store.
 *
 * <p>Failures are logged at WARN and swallowed. Never block dead-lettering on
 * cleanup. Nothing else removes a slot left behind (see docs/architecture.md#key-custody-and-trust).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CheckpointStagingPurger {

    private final SecretStore secretStore;

    /** No-op if the message has no checkpoint, or no {@code PrivateKeyKvPath}. */
    public void purgeIfPresent(InboundMessage message) {
        if (message == null) return;
        Object pathObj = message.getApplicationProperties()
                .get(IssuanceCheckpoint.PROP_PRIVATE_KEY_KV_PATH);
        if (pathObj == null) return;
        String path = pathObj.toString();
        if (path.isBlank()) return;
        try {
            secretStore.delete(path);
            log.info("Purged staging slot on RETRY_GIVE_UP: {}", path);
        } catch (Exception e) {
            log.warn("Failed to purge staging slot on RETRY_GIVE_UP; the slot stays in the store: path={} error={}",
                    path, e.getMessage());
        }
    }
}
