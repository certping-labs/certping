// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.startup;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.secrets.SecretStoreProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecretStoreStartupValidatorTest {

    private static final String PROBE_HANDLE = "https://kv.vault.azure.net/secrets/startup-probe";

    @Mock private SecretStore secretStore;

    private SecretStoreStartupValidator validator;

    @BeforeEach
    void setUp() {
        validator = new SecretStoreStartupValidator(secretStore);
        lenient().when(secretStore.handleFor("startup-probe")).thenReturn(PROBE_HANDLE);
        lenient().when(secretStore.provider()).thenReturn(SecretStoreProvider.AZURE_KV);
    }

    @Test
    void secretNotFound_logsOkAndDoesNotThrow() {
        when(secretStore.read(PROBE_HANDLE))
                .thenThrow(new PermanentAgentException("KV_SECRET_NOT_FOUND", "404"));

        validator.validateAccess();

        verify(secretStore).read(PROBE_HANDLE);
    }

    @Test
    void accessDenied_logsWarningAndDoesNotThrow() {
        when(secretStore.read(PROBE_HANDLE))
                .thenThrow(new PermanentAgentException("KV_ACCESS_DENIED", "403 Forbidden"));

        validator.validateAccess();

        verify(secretStore).read(PROBE_HANDLE);
    }

    @Test
    void otherPermanentError_logsWarningAndDoesNotThrow() {
        when(secretStore.read(PROBE_HANDLE))
                .thenThrow(new PermanentAgentException("KV_URI_INVALID", "bad URI"));

        validator.validateAccess();

        verify(secretStore).read(PROBE_HANDLE);
    }

    @Test
    void networkException_logsWarningAndDoesNotThrow() {
        when(secretStore.read(PROBE_HANDLE))
                .thenThrow(new TransientAgentException("KV_NETWORK_ERROR", "connection refused"));

        validator.validateAccess();

        verify(secretStore).read(PROBE_HANDLE);
    }

    @Test
    void probeSecretExists_logsOkAndDoesNotThrow() {
        when(secretStore.read(PROBE_HANDLE)).thenReturn("unexpected-value");

        validator.validateAccess();

        verify(secretStore).read(PROBE_HANDLE);
    }

    @Test
    void handleForThrows_skipsProbeWithoutReading() {
        when(secretStore.handleFor("startup-probe"))
                .thenThrow(new IllegalStateException("secret store not configured"));

        validator.validateAccess();

        verify(secretStore, never()).read(anyString());
    }
}
