// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeyStagingHelperTest {

    private static final String PATH = "https://kv.vault.azure.net/secrets/cert-1-key-staging/v1";

    @Mock private SecretStore secretStore;

    @Test
    void readsBackWhatStageWrote() {
        when(secretStore.create(anyString(), anyString())).thenAnswer(inv -> {
            when(secretStore.read(PATH)).thenReturn(inv.getArgument(1));
            return PATH;
        });
        KeyStagingHelper helper = new KeyStagingHelper(secretStore);

        assertThat(helper.stage("cert-1", "KEY", "CSR")).isEqualTo(PATH);
        assertThat(helper.read(PATH)).isEqualTo(new KeyStagingHelper.Staged("KEY", "CSR"));
    }

    @Test
    void aSlotThatIsGoneIsRetriedShortly() {
        when(secretStore.read(PATH)).thenThrow(new PermanentAgentException("KV_SECRET_NOT_FOUND", "Secret not found at handle: " + PATH));

        assertThatThrownBy(() -> new KeyStagingHelper(secretStore).read(PATH))
                .isInstanceOfSatisfying(RetryableAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo(KeyStagingHelper.STAGED_KEY_MISSING);
                    assertThat(e.getRetryAfter()).isEqualTo(KeyStagingHelper.MISSING_RETRY_AFTER);
                    assertThat(e.getCause()).isInstanceOf(PermanentAgentException.class);
                });
    }

    @Test
    void otherPermanentFailuresPassThrough() {
        when(secretStore.read(PATH)).thenThrow(new PermanentAgentException("KV_FORBIDDEN", "no access"));

        assertThatThrownBy(() -> new KeyStagingHelper(secretStore).read(PATH))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessage("no access");
    }

    @Test
    void aCorruptSlotIsPermanent() {
        when(secretStore.read(PATH)).thenReturn("not a staged key");

        assertThatThrownBy(() -> new KeyStagingHelper(secretStore).read(PATH))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("STAGED_KEY_CORRUPT"));
    }
}
