// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.credential;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EmulatorCredentialTest {

    @Test
    void getToken_returnsFutureBearerToken() {
        AccessToken token = new EmulatorCredential().getToken(new TokenRequestContext()).block();

        assertThat(token).isNotNull();
        assertThat(token.getToken()).contains(".");
        assertThat(token.getExpiresAt()).isAfter(java.time.OffsetDateTime.now());
    }
}