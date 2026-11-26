// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CheckpointStagingPurgerTest {

    @Mock private SecretStore secretStore;
    @Mock private InboundMessage message;

    private CheckpointStagingPurger purger;

    @BeforeEach
    void setUp() {
        purger = new CheckpointStagingPurger(secretStore);
    }

    @Test
    void purgeIfPresent_nullMessage_isNoOp() {
        purger.purgeIfPresent(null);
        verify(secretStore, never()).delete(anyString());
    }

    @Test
    void purgeIfPresent_noCheckpointProperty_isNoOp() {
        when(message.getApplicationProperties()).thenReturn(new HashMap<>());
        purger.purgeIfPresent(message);
        verify(secretStore, never()).delete(anyString());
    }

    @Test
    void purgeIfPresent_blankPath_isNoOp() {
        Map<String, Object> props = new HashMap<>();
        props.put(IssuanceCheckpoint.PROP_PRIVATE_KEY_KV_PATH, "   ");
        when(message.getApplicationProperties()).thenReturn(props);

        purger.purgeIfPresent(message);

        verify(secretStore, never()).delete(anyString());
    }

    @Test
    void purgeIfPresent_validPath_deletesSecret() {
        Map<String, Object> props = new HashMap<>();
        props.put(IssuanceCheckpoint.PROP_PRIVATE_KEY_KV_PATH,
                "https://kv.vault.azure.net/secrets/cert-key-staging");
        when(message.getApplicationProperties()).thenReturn(props);

        purger.purgeIfPresent(message);

        verify(secretStore).delete(
                "https://kv.vault.azure.net/secrets/cert-key-staging");
    }

    @Test
    void purgeIfPresent_kvThrows_swallowedNotRethrown() {
        Map<String, Object> props = new HashMap<>();
        props.put(IssuanceCheckpoint.PROP_PRIVATE_KEY_KV_PATH,
                "https://kv.vault.azure.net/secrets/x");
        when(message.getApplicationProperties()).thenReturn(props);
        doThrow(new RuntimeException("KV outage"))
                .when(secretStore).delete(anyString());

        // Never propagate — the WARN log path is the observable contract.
        purger.purgeIfPresent(message);

        verify(secretStore).delete(anyString());
    }
}
