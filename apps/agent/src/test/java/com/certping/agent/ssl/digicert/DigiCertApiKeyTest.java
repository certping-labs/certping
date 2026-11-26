// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.digicert;

import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DigiCertApiKeyTest {

    @Test
    void readsTheApiKeyCertManagerStores() {
        assertThat(DigiCertApiKey.from(" {\"apiKey\":\" dc-key-1 \",\"extra\":1} ")).isEqualTo("dc-key-1");
    }

    @Test
    void readsABareKeyAsIs() {
        assertThat(DigiCertApiKey.from("  dc-key-2\n")).isEqualTo("dc-key-2");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "{}", "{\"apiKey\":\"  \"}", "{\"apiKey\":7}"})
    void refusesASecretWithoutAKey(String secret) {
        assertThatThrownBy(() -> DigiCertApiKey.from(secret))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("no API key");
    }

    @Test
    void refusesMalformedJson() {
        assertThatThrownBy(() -> DigiCertApiKey.from("{\"apiKey\":"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("not valid JSON");
    }

    @Test
    void refusesANullSecret() {
        assertThatThrownBy(() -> DigiCertApiKey.from(null)).isInstanceOf(PermanentAgentException.class);
    }
}
