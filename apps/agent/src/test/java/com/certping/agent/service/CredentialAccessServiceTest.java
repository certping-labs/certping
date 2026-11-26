// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.service;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialAccessServiceTest {

    @Mock private SecretStore secretStore;

    private CredentialAccessService service;

    @BeforeEach
    void setUp() {
        service = new CredentialAccessService(secretStore);
    }

    @Test
    void readSecret_delegatesToKeyVaultService() {
        String uri = "https://client-kv.vault.azure.net/secrets/my-cred";
        when(secretStore.read(uri)).thenReturn("plain-api-token");

        String result = service.readSecret(uri);

        assertThat(result).isEqualTo("plain-api-token");
        verify(secretStore).read(uri);
    }

    @Test
    void readSecret_propagatesPermanentException() {
        String uri = "https://client-kv.vault.azure.net/secrets/missing";
        when(secretStore.read(uri))
                .thenThrow(new PermanentAgentException("KV_SECRET_NOT_FOUND", "secret not found"));

        assertThatThrownBy(() -> service.readSecret(uri))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KV_SECRET_NOT_FOUND"));
    }

    @Test
    void readSecret_propagatesTransientException() {
        String uri = "https://client-kv.vault.azure.net/secrets/my-cred";
        when(secretStore.read(uri))
                .thenThrow(new TransientAgentException("KV_NETWORK_ERROR", "transient"));

        assertThatThrownBy(() -> service.readSecret(uri))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void readSecret_propagatesAccessDeniedException() {
        String uri = "https://client-kv.vault.azure.net/secrets/restricted";
        when(secretStore.read(uri))
                .thenThrow(new PermanentAgentException("KV_ACCESS_DENIED", "403 Forbidden"));

        assertThatThrownBy(() -> service.readSecret(uri))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KV_ACCESS_DENIED"));
    }

    @Test
    void readSecret_returnsRawStringWithoutParsing() {
        String uri = "https://client-kv.vault.azure.net/secrets/json-cred";
        String jsonValue = "{\"accessKeyId\":\"AKIA123\",\"secretAccessKey\":\"secret\"}";
        when(secretStore.read(uri)).thenReturn(jsonValue);

        String result = service.readSecret(uri);

        assertThat(result).isEqualTo(jsonValue);
    }
}
